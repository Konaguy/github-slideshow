"""Chaos / resilience testing (charter §6 Phase 4).

Phase 4 calls for "chaos/resilience testing" as GA-hardening work. The
premise of the whole product is that regeneration is reliable enough to
sell an RTO/RPO number against (§4: <5 min, <1 min, >99.9% success), and
the only honest way to claim that is to break things on purpose and check
the guarantees still hold.

Each scenario injects one fault, runs a real regeneration through the
real orchestrator, and asserts the invariants that must survive it:

  1. regeneration completes at all
  2. RTO/RPO stay inside the §4 targets
  3. clean user data comes back
  4. no quarantined/malicious file gets restored
  5. the forensic custody chain still verifies

A scenario "passes" only if every invariant holds. A scenario that fails
is reporting a real weakness in the recovery path -- that is the point of
running it.

Fault coverage is limited to what this prototype can actually break:
storage provider outages, blob loss, baseline drift, vault tampering.
A production chaos suite would also kill processes mid-regeneration, run
out of disk during restore, partition the network between control plane
and providers, corrupt a snapshot manifest, and inject clock skew --
several of which need infrastructure this prototype doesn't have.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from phantom.metrics import RPO_TARGET_SECONDS, RTO_TARGET_SECONDS


@dataclass
class ScenarioResult:
    name: str
    passed: bool
    detail: str
    violations: list = field(default_factory=list)

    def summary(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        lines = [f"[{status}] {self.name}: {self.detail}"]
        for violation in self.violations:
            lines.append(f"         violated: {violation}")
        return "\n".join(lines)


@dataclass
class ChaosReport:
    results: list

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    def summary(self) -> str:
        lines = [r.summary() for r in self.results]
        passed = sum(1 for r in self.results if r.passed)
        lines.append("")
        lines.append(f"{passed}/{len(self.results)} scenarios passed")
        return "\n".join(lines)


def check_invariants(phantom, report, expected_files: dict) -> list:
    """The guarantees every scenario must preserve. Returns violations."""
    violations = []

    if report is None:
        return ["regeneration did not complete"]

    if not report.rto_pass:
        violations.append(f"RTO {report.rto_seconds:.2f}s exceeded target {RTO_TARGET_SECONDS}s")
    if not report.rpo_pass:
        violations.append(f"RPO {report.rpo_seconds:.2f}s exceeded target {RPO_TARGET_SECONDS}s")

    for relpath, expected_content in expected_files.items():
        path = phantom.instance.data_dir / relpath
        if not path.exists():
            violations.append(f"clean file {relpath!r} was not restored")
        elif path.read_text() != expected_content:
            violations.append(f"restored {relpath!r} does not match pre-attack content")

    # Nothing the sanitizer quarantined may exist in the live instance.
    for quarantine_batch in sorted(phantom.quarantine.root.glob("*/files")) if phantom.quarantine.root.exists() else []:
        for quarantined in quarantine_batch.rglob("*"):
            if quarantined.is_file():
                relpath = quarantined.relative_to(quarantine_batch)
                if (phantom.instance.data_dir / relpath).exists():
                    violations.append(f"quarantined file {str(relpath)!r} was restored into the live instance")

    custody_problems = phantom.vault.verify_chain()
    if custody_problems:
        violations.append(f"forensic custody chain broken: {custody_problems[0]}")

    return violations


class ChaosRunner:
    """Runs fault-injection scenarios against a PhantomInstance factory.

    `make_instance` must return a *fresh* PhantomInstance on each call --
    scenarios destroy state, so they cannot share one.
    """

    def __init__(self, make_instance: Callable, seed: Optional[int] = None):
        self.make_instance = make_instance
        self.random = random.Random(seed)

    # -- shared setup -------------------------------------------------

    def _seeded_instance(self):
        """A fresh instance with known-good user data already snapshotted."""
        phantom = self.make_instance()
        phantom.init()
        expected = {
            "notes.txt": "quarterly numbers are steady and this is plain readable text",
            "budget.csv": "revenue,cost\n100,50\n200,75\n",
        }
        for relpath, content in expected.items():
            phantom.write_user_file(relpath, content)
        phantom.take_snapshot()
        return phantom, expected

    # -- scenarios ------------------------------------------------------

    def scenario_provider_outage(self) -> ScenarioResult:
        """One storage region goes dark before recovery starts."""
        phantom, expected = self._seeded_instance()
        downed = phantom.backup.providers[0].name
        phantom.backup.set_outage(downed, down=True)

        report = phantom.regenerate(reason="chaos: provider outage")
        violations = check_invariants(phantom, report, expected)
        return ScenarioResult(
            name="provider_outage",
            passed=not violations,
            detail=f"regenerated with provider {downed!r} unavailable",
            violations=violations,
        )

    def scenario_majority_provider_outage(self) -> ScenarioResult:
        """All but one region goes dark -- recovery must still work."""
        phantom, expected = self._seeded_instance()
        downed = [p.name for p in phantom.backup.providers[:-1]]
        for name in downed:
            phantom.backup.set_outage(name, down=True)

        report = phantom.regenerate(reason="chaos: majority provider outage")
        violations = check_invariants(phantom, report, expected)
        return ScenarioResult(
            name="majority_provider_outage",
            passed=not violations,
            detail=f"regenerated with only 1 of {len(phantom.backup.providers)} providers reachable",
            violations=violations,
        )

    def scenario_attack_then_outage(self) -> ScenarioResult:
        """Compound failure: compromised AND a region is down."""
        phantom, expected = self._seeded_instance()
        phantom.simulate_attack()
        phantom.take_snapshot()
        phantom.backup.set_outage(phantom.backup.providers[0].name, down=True)

        report = phantom.regenerate(reason="chaos: attack during provider outage")
        violations = check_invariants(phantom, report, expected)
        if (phantom.instance.data_dir / "RANSOM_NOTE_README.txt").exists():
            violations.append("ransom note survived into the regenerated instance")
        return ScenarioResult(
            name="attack_then_outage",
            passed=not violations,
            detail="regenerated from a compromised snapshot with a region down",
            violations=violations,
        )

    def scenario_baseline_drift(self) -> ScenarioResult:
        """The immutable baseline is tampered with. Regeneration must REFUSE
        rather than spawn from an untrusted image.
        """
        from phantom.baseline import BaselineIntegrityError

        phantom, _expected = self._seeded_instance()
        policy_file = phantom.baseline_dir / "etc" / "security-policy.conf"
        policy_file.write_text("hardened=false\nbackdoor=enabled\n")

        try:
            phantom.regenerate(reason="chaos: baseline drift")
        except BaselineIntegrityError:
            return ScenarioResult(
                name="baseline_drift",
                passed=True,
                detail="regeneration correctly refused to spawn from a drifted baseline",
            )
        return ScenarioResult(
            name="baseline_drift",
            passed=False,
            detail="regeneration proceeded from a tampered baseline",
            violations=["spawned an instance from an untrusted baseline image"],
        )

    def scenario_vault_tampering_detected(self) -> ScenarioResult:
        """Evidence is altered post-capture; the custody chain must catch it."""
        phantom, _expected = self._seeded_instance()
        phantom.regenerate(reason="chaos: vault tampering setup")

        entries = phantom.vault.entries()
        if not entries:
            return ScenarioResult(
                name="vault_tampering_detected", passed=False,
                detail="no custody entry was written to tamper with",
                violations=["regeneration did not produce forensic evidence"],
            )

        artifacts = phantom.vault.root / entries[0].case_id / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / "notes.txt").write_text("evidence quietly rewritten")

        problems = phantom.vault.verify_chain()
        return ScenarioResult(
            name="vault_tampering_detected",
            passed=bool(problems),
            detail="custody chain flagged post-capture evidence tampering" if problems
                   else "custody chain did NOT detect tampering",
            violations=[] if problems else ["tampered evidence verified as intact"],
        )

    def scenario_random_multi_outage(self) -> ScenarioResult:
        """Randomized: take a random subset of regions down, leaving >=1 up."""
        phantom, expected = self._seeded_instance()
        providers = phantom.backup.providers
        down_count = self.random.randint(1, max(1, len(providers) - 1))
        downed = self.random.sample([p.name for p in providers], down_count)
        for name in downed:
            phantom.backup.set_outage(name, down=True)

        report = phantom.regenerate(reason="chaos: randomized outage")
        violations = check_invariants(phantom, report, expected)
        return ScenarioResult(
            name="random_multi_outage",
            passed=not violations,
            detail=f"regenerated with {sorted(downed)} unavailable",
            violations=violations,
        )

    # -- driver -----------------------------------------------------------

    ALL_SCENARIOS = [
        "scenario_provider_outage",
        "scenario_majority_provider_outage",
        "scenario_attack_then_outage",
        "scenario_baseline_drift",
        "scenario_vault_tampering_detected",
        "scenario_random_multi_outage",
    ]

    def run_all(self) -> ChaosReport:
        results = []
        for name in self.ALL_SCENARIOS:
            scenario = getattr(self, name)
            try:
                results.append(scenario())
            except Exception as exc:  # a crash is a failed scenario, not a crashed suite
                results.append(ScenarioResult(
                    name=name.replace("scenario_", ""),
                    passed=False,
                    detail=f"scenario raised {type(exc).__name__}: {exc}",
                    violations=["unhandled exception during recovery"],
                ))
        return ChaosReport(results=results)
