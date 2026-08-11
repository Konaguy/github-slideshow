"""Behavioral drift detection between consecutive snapshots (charter §5.D).

§5.A notes the snapshot engine "doubles as the training-data source for
behavioral detection (see D)," and §5.D describes a "model trained on
inter-snapshot behavioral drift per machine. Anomalous deltas trigger
regeneration. Snapshot engine and detection engine share one data
pipeline." That shared pipeline is real here -- this module consumes
exactly the `Snapshot` manifests the snapshot engine already produces, no
separate agent or collection path.

What is NOT real here is the model. The charter's "AI-vs-AI" engine is a
trained behavioral model; this is a weighted-signal scorer with
hand-tuned thresholds. It is a stand-in that establishes the interface a
trained model would sit behind (`DetectionEngine.evaluate` -> a score plus
the signals that produced it), and it deliberately keys on the
*shape* of a ransomware-style delta rather than on any specific payload:

  - mass_rewrite:  a large fraction of existing files changed at once
  - mass_deletion:  a large fraction of existing files disappeared at once
  - entropy_spike:   files that were low-entropy text became high-entropy
  - suspicious_arrivals: newly-added files that trip the sanitize rules

A real deployment would also weigh process behavior, network context, and
identity signals (§1.1 step 1) -- none of which this file-level prototype
observes. Scores here should be read as "this delta looks structurally
like an attack," not as a confident verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from phantom.sanitize import DEFAULT_RULES, shannon_entropy
from phantom.snapshot import INTERVAL, POST_REGENERATION

# Score contributions per signal, weighted by how much each one means on
# its own. entropy_spike (text became random), mass_deletion (wiper
# behavior), and suspicious_arrivals (a dropped ransom note) each clear
# DEFAULT_THRESHOLD unaided. mass_rewrite deliberately does not: a bulk
# rewrite with no entropy change is just as likely a formatter, a sync, or
# a find-and-replace, and regenerating someone's desktop over that is a
# worse outcome than waiting for a second signal.
WEIGHTS = {
    "mass_rewrite": 0.4,
    "mass_deletion": 0.6,
    "entropy_spike": 0.7,
    "suspicious_arrivals": 0.5,
}

DEFAULT_THRESHOLD = 0.5
MASS_CHANGE_FRACTION = 0.5  # >=50% of prior files touched at once
# Below this many files, "50% of them changed" is noise -- editing your
# only two documents is not a mass rewrite. Fraction-based signals are
# suppressed entirely under this count.
MIN_FILES_FOR_MASS_SIGNAL = 5
ENTROPY_SPIKE_DELTA = 2.0  # bits/byte jump that reads as "was text, now isn't"
ENTROPY_MIN_SIZE = 64  # entropy on tiny samples is noise


@dataclass
class Signal:
    name: str
    weight: float
    detail: str


@dataclass
class DetectionResult:
    score: float
    threshold: float
    signals: list = field(default_factory=list)

    @property
    def is_anomalous(self) -> bool:
        return self.score >= self.threshold

    def summary(self) -> str:
        if not self.signals:
            return f"No behavioral drift detected (score {self.score:.2f} < {self.threshold:.2f})"
        lines = [
            f"{'ANOMALY' if self.is_anomalous else 'below threshold'}: "
            f"score {self.score:.2f} (threshold {self.threshold:.2f})"
        ]
        for signal in self.signals:
            lines.append(f"  [{signal.name} +{signal.weight:.2f}] {signal.detail}")
        return "\n".join(lines)


class DetectionEngine:
    """Scores the delta between two snapshots. `read_blob` resolves content
    hashes so entropy can be measured -- same store the snapshot engine writes to.
    """

    def __init__(self, read_blob, threshold: float = DEFAULT_THRESHOLD):
        self.read_blob = read_blob
        self.threshold = threshold

    def evaluate(self, previous, current) -> DetectionResult:
        """previous/current are Snapshot objects; previous may be None (first snapshot)."""
        if previous is None:
            return DetectionResult(score=0.0, threshold=self.threshold, signals=[])

        # A post-regeneration snapshot is Phantom's own recovery: every file
        # legitimately changed at once because we just rebuilt from a clean
        # baseline. Scoring that delta would have the product flag its own
        # remediation as an attack -- and since the response to an anomaly is
        # another regeneration, that is a rebuild loop waiting for someone to
        # nudge a weight upward.
        if getattr(current, "kind", INTERVAL) == POST_REGENERATION:
            return DetectionResult(score=0.0, threshold=self.threshold, signals=[])

        prior_paths = set(previous.files)
        current_paths = set(current.files)
        signals = []

        if prior_paths:
            surviving = prior_paths & current_paths
            rewritten = {p for p in surviving if previous.files[p] != current.files[p]}
            deleted = prior_paths - current_paths
            mass_signals_meaningful = len(prior_paths) >= MIN_FILES_FOR_MASS_SIGNAL

            if mass_signals_meaningful and len(rewritten) / len(prior_paths) >= MASS_CHANGE_FRACTION:
                signals.append(Signal(
                    "mass_rewrite", WEIGHTS["mass_rewrite"],
                    f"{len(rewritten)}/{len(prior_paths)} existing files rewritten in one interval",
                ))

            if mass_signals_meaningful and len(deleted) / len(prior_paths) >= MASS_CHANGE_FRACTION:
                signals.append(Signal(
                    "mass_deletion", WEIGHTS["mass_deletion"],
                    f"{len(deleted)}/{len(prior_paths)} existing files deleted in one interval",
                ))

            spiked = self._entropy_spikes(previous, current, rewritten)
            if spiked:
                signals.append(Signal(
                    "entropy_spike", WEIGHTS["entropy_spike"],
                    f"{len(spiked)} file(s) jumped >= {ENTROPY_SPIKE_DELTA} bits/byte entropy "
                    f"(e.g. {sorted(spiked)[0]}); consistent with in-place encryption",
                ))

        arrivals = current_paths - prior_paths
        flagged = self._suspicious_arrivals(current, arrivals)
        if flagged:
            signals.append(Signal(
                "suspicious_arrivals", WEIGHTS["suspicious_arrivals"],
                f"{len(flagged)} newly-added file(s) trip sanitize rules (e.g. {sorted(flagged)[0]})",
            ))

        score = min(1.0, sum((s.weight for s in signals), 0.0))
        return DetectionResult(score=score, threshold=self.threshold, signals=signals)

    def _entropy_spikes(self, previous, current, rewritten) -> list:
        spiked = []
        for relpath in rewritten:
            try:
                before = self.read_blob(previous.files[relpath])
                after = self.read_blob(current.files[relpath])
            except Exception:
                continue  # unreadable blob is a storage problem, not a detection signal
            if len(before) < ENTROPY_MIN_SIZE or len(after) < ENTROPY_MIN_SIZE:
                continue
            if shannon_entropy(after) - shannon_entropy(before) >= ENTROPY_SPIKE_DELTA:
                spiked.append(relpath)
        return spiked

    def _suspicious_arrivals(self, current, arrivals) -> list:
        flagged = []
        for relpath in arrivals:
            try:
                content = self.read_blob(current.files[relpath])
            except Exception:
                continue
            if any(rule(relpath, content) is not None for rule in DEFAULT_RULES):
                flagged.append(relpath)
        return flagged
