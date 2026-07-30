"""Deception Layer / honeypot migration (charter §5.G, Phase 4).

§5.G: "Compromised instance migrated live into a quarantined honeypot
clone: attacker continues in sandbox while the real user regenerates
elsewhere. Tooling and TTPs harvested."

The charter marks this module "(optional)" and constrains it harder than
anything else in the product:

  §8 Assumptions: "Deception layer is opt-in per customer (legal/risk
                   review required)."
  §9 Risks:       "Deception layer legal exposure -- Medium -- Opt-in
                   module, legal review, jurisdiction-aware defaults."
  §10 Open:       "Deception layer: build in-house or partner with an
                   existing honeypot vendor?"

So the gate is the feature. `DeceptionPolicy.evaluate()` is default-deny
and requires three independent conditions before a single byte is
migrated: the module explicitly enabled, a recorded legal-review
acknowledgement naming who signed off and when, and the operating
jurisdiction present in an operator-configured allowlist.

On jurisdictions -- deliberately NOT encoded here: this module ships with
an EMPTY allowlist and no built-in opinion about which jurisdictions
permit deception, retention of an intruder's session, or harvesting their
tooling. Those questions turn on local law, the customer's contracts, and
the specific deployment; encoding a guess would be inventing legal advice
that operators might rely on. The allowlist is something counsel fills in
per deployment. Empty allowlist = deception never runs, which is the
correct default for a module nobody has reviewed yet.

Scope: this is containment-and-observation of an already-compromised
workload the customer owns -- the sandbox exists so the attacker keeps
working against a decoy while the real user regenerates elsewhere. It
observes what happens to files inside that sandbox. It does not reach
back toward whoever is on the other end, and nothing here should grow in
that direction: "hack back" is a different thing wearing this thing's
vocabulary, and it is not in the charter.

The sandbox is a local directory with an isolation marker, not a real
network-isolated VM. A production build needs genuine network isolation
(no lateral path back to production, no egress that lets the sandbox be
used as a launch point), a believable synthetic environment, and per §10
possibly a honeypot vendor rather than in-house tooling.
"""
from __future__ import annotations

import json
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from phantom.sanitize import compute_hash


@dataclass
class DeceptionConfig:
    """Per-customer opt-in state. Every field defaults to the safe answer."""
    enabled: bool = False
    jurisdiction: Optional[str] = None
    legal_review_ack: bool = False
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    # Operator-configured; empty means "no jurisdiction has been cleared."
    permitted_jurisdictions: list = field(default_factory=list)


@dataclass
class GateDecision:
    permitted: bool
    reasons: list  # why it was denied; empty when permitted

    def summary(self) -> str:
        if self.permitted:
            return "Deception permitted: opt-in, legal review, and jurisdiction checks all satisfied"
        return "Deception DENIED:\n" + "\n".join(f"  - {r}" for r in self.reasons)


class DeceptionPolicy:
    """Default-deny gate in front of the honeypot."""

    def __init__(self, path: Path):
        self.path = path

    def load(self) -> DeceptionConfig:
        if not self.path.exists():
            return DeceptionConfig()
        return DeceptionConfig(**json.loads(self.path.read_text()))

    def save(self, config: DeceptionConfig) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(asdict(config), indent=2))

    def enable(self, jurisdiction: str, reviewed_by: str,
               permitted_jurisdictions: Optional[list] = None) -> DeceptionConfig:
        """Record an opt-in. `reviewed_by` is who accepted the legal risk.

        Note this does NOT itself permit anything: if `jurisdiction` is not
        in the allowlist, `evaluate()` still denies. Enabling and clearing
        a jurisdiction are separate acts on purpose.
        """
        config = self.load()
        config.enabled = True
        config.jurisdiction = jurisdiction
        config.legal_review_ack = True
        config.reviewed_by = reviewed_by
        config.reviewed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if permitted_jurisdictions is not None:
            config.permitted_jurisdictions = list(permitted_jurisdictions)
        self.save(config)
        return config

    def disable(self) -> DeceptionConfig:
        config = self.load()
        config.enabled = False
        self.save(config)
        return config

    def evaluate(self) -> GateDecision:
        """Default-deny. All three conditions must hold independently."""
        config = self.load()
        reasons = []

        if not config.enabled:
            reasons.append("deception module is not enabled for this customer (opt-in required, §8)")
        if not config.legal_review_ack:
            reasons.append("no legal/risk review acknowledgement on record (§8, §9)")
        if not config.jurisdiction:
            reasons.append("no operating jurisdiction declared")
        elif config.jurisdiction not in config.permitted_jurisdictions:
            reasons.append(
                f"jurisdiction {config.jurisdiction!r} is not in the operator-configured "
                f"allowlist {config.permitted_jurisdictions or '(empty)'} -- counsel must clear it explicitly (§9)"
            )

        return GateDecision(permitted=not reasons, reasons=reasons)


@dataclass
class TTPObservation:
    """One harvested artifact from the sandbox. Content hash + metadata only."""
    relpath: str
    content_hash: str
    size_bytes: int
    observed_at: str
    note: str


class Honeypot:
    """A quarantined clone of a compromised instance.

    `migrate` copies the compromised data into an isolated sandbox so the
    attacker's session continues against a decoy while the real instance
    is destroyed and regenerated. `harvest` records what is present in the
    sandbox as TTP observations (hashes and metadata, never contents) that
    can be fed to the threat-intel feed.
    """

    ISOLATION_MARKER = ".quarantined"

    def __init__(self, root: Path):
        self.root = root
        self.sandbox_dir = root / "sandbox"
        self.observations_path = root / "ttp_observations.jsonl"

    def is_quarantined(self) -> bool:
        return (self.root / self.ISOLATION_MARKER).exists()

    def migrate(self, source_data_dir: Path, case_id: str) -> Path:
        """Clone the compromised data into the isolated sandbox."""
        session_dir = self.sandbox_dir / case_id
        if source_data_dir.exists():
            shutil.copytree(source_data_dir, session_dir, dirs_exist_ok=True)
        else:
            session_dir.mkdir(parents=True, exist_ok=True)

        self.root.mkdir(parents=True, exist_ok=True)
        # Stand-in for real network isolation -- see module docstring. A
        # production sandbox must be unable to reach production or egress.
        (self.root / self.ISOLATION_MARKER).write_text(
            json.dumps({
                "quarantined_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "isolation": "simulated (local directory); production requires real network isolation",
            }, indent=2)
        )
        return session_dir

    def harvest(self, session_dir: Path, note: str = "artifact present at migration") -> list:
        """Record hashes/metadata of sandbox artifacts as TTP observations."""
        observations = []
        for path in sorted(p for p in session_dir.rglob("*") if p.is_file()):
            content = path.read_bytes()
            observations.append(TTPObservation(
                relpath=str(path.relative_to(session_dir)),
                content_hash=compute_hash(content),
                size_bytes=len(content),
                observed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                note=note,
            ))

        if observations:
            self.observations_path.parent.mkdir(parents=True, exist_ok=True)
            with self.observations_path.open("a") as fh:
                for observation in observations:
                    fh.write(json.dumps(asdict(observation)) + "\n")
        return observations

    def observations(self) -> list:
        if not self.observations_path.exists():
            return []
        return [
            TTPObservation(**json.loads(line))
            for line in self.observations_path.read_text().splitlines() if line.strip()
        ]

    def harvested_hashes(self) -> set:
        """Content hashes suitable for publishing to the threat-intel feed."""
        return {o.content_hash for o in self.observations()}
