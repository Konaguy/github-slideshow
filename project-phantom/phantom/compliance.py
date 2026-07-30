"""Control-evidence reporting (charter §5.J, §6 Phase 4).

§5.J lists "audit logging, compliance (SOC 2 v1: FedRAMP future)" under
Enterprise Integration, and Phase 4 carries "compliance certification."

READ THIS BEFORE USING THE OUTPUT
---------------------------------
This module does not certify anything, and running it does not make a
deployment compliant. Certification is an audit performed by a licensed
firm against evidence covering a defined observation period; no program
can self-attest its way there, and a passing report here means only that
Phantom's own logs contain the events described.

What this actually does: read the audit log, forensic vault, and policy
state, and answer "what evidence do we already have, and what is
missing?" -- so the gaps surface before an auditor finds them. The
control mapping below is a STARTING POINT for a conversation with an
auditor, not a validated mapping. Which criteria apply, what evidence
satisfies them, and what the observation period must cover are all
determinations for the auditor and the customer's compliance team.

Specific limits worth stating plainly:
  - Evidence is drawn from Phantom's own audit log, which is a plain
    append-only file. An auditor will ask what stops an administrator
    editing it; the honest answer today is "nothing" -- the forensic
    vault is hash-chained, the audit log is not.
  - Several real criteria (personnel, change management, vendor
    management, physical security) have no Phantom-side evidence at all
    and are deliberately absent rather than stubbed as "passing."
  - Coverage counts events, not effectiveness. "12 regenerations logged"
    is not "recovery works"; the chaos suite (phantom/chaos.py) is the
    closer thing to evidence of effectiveness.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

DISCLAIMER = (
    "This report is evidence-gathering input for an audit. It is NOT a certification, "
    "attestation, or determination of compliance. Control mappings are a starting point "
    "requiring validation by a qualified auditor."
)


@dataclass
class ControlEvidence:
    control_id: str
    objective: str
    evidence_source: str
    event_count: int
    satisfied: bool
    findings: list = field(default_factory=list)


@dataclass
class ComplianceReport:
    generated_at: str
    disclaimer: str
    controls: list
    gaps: list

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def summary(self) -> str:
        lines = [
            f"Control evidence report -- {self.generated_at}",
            "",
            DISCLAIMER,
            "",
        ]
        for control in self.controls:
            mark = "evidence present" if control.satisfied else "NO EVIDENCE"
            lines.append(f"  [{mark}] {control.control_id}: {control.objective}")
            lines.append(f"      source: {control.evidence_source}  events: {control.event_count}")
            for finding in control.findings:
                lines.append(f"      finding: {finding}")
        if self.gaps:
            lines.append("")
            lines.append("Gaps an auditor will raise:")
            for gap in self.gaps:
                lines.append(f"  - {gap}")
        return "\n".join(lines)


# Control objectives Phantom can produce evidence for. The ids are the
# commonly-cited SOC 2 Trust Services Criteria numbers, included because
# they are what a compliance team will ask about -- NOT because this
# mapping has been validated. See the module docstring.
CONTROL_MAP = [
    {
        "control_id": "CC7.2",
        "objective": "Monitor system components for anomalies indicative of malicious acts",
        "events": ["detection_evaluated"],
    },
    {
        "control_id": "CC7.3",
        "objective": "Evaluate security events to determine whether they constitute an incident",
        "events": ["regeneration_triggered"],
    },
    {
        "control_id": "CC7.4",
        "objective": "Respond to identified security incidents",
        "events": ["instance_regenerated", "data_restored"],
    },
    {
        "control_id": "CC7.5",
        "objective": "Recover from identified security incidents",
        "events": ["regeneration_complete"],
    },
    {
        "control_id": "A1.2",
        "objective": "Maintain backup/recovery infrastructure to meet availability commitments",
        "events": ["snapshot_taken"],
    },
    {
        "control_id": "A1.3",
        "objective": "Test recovery procedures",
        "events": ["chaos_suite_run"],
    },
]

# Criteria a real audit covers that Phantom has no visibility into. Listed
# explicitly so the report cannot be mistaken for full coverage.
OUT_OF_SCOPE_CRITERIA = [
    "CC1.x (control environment / personnel): no Phantom-side evidence",
    "CC6.x (logical & physical access controls): identity and access are outside this prototype",
    "CC8.1 (change management): no Phantom-side evidence",
    "CC9.2 (vendor management): no Phantom-side evidence",
]


class ComplianceReporter:
    def __init__(self, audit_log, vault, policy):
        self.audit_log = audit_log
        self.vault = vault
        self.policy = policy

    def _all_events(self) -> list:
        if not self.audit_log.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.audit_log.path.read_text().splitlines() if line.strip()
        ]

    def generate(self) -> ComplianceReport:
        events = self._all_events()
        counts = {}
        for event in events:
            counts[event.get("event")] = counts.get(event.get("event"), 0) + 1

        controls = []
        for spec in CONTROL_MAP:
            count = sum(counts.get(name, 0) for name in spec["events"])
            findings = []
            if count == 0:
                findings.append(
                    f"no {' or '.join(spec['events'])} events in the audit log for the period"
                )
            controls.append(ControlEvidence(
                control_id=spec["control_id"],
                objective=spec["objective"],
                evidence_source=f"audit log events: {', '.join(spec['events'])}",
                event_count=count,
                satisfied=count > 0,
                findings=findings,
            ))

        return ComplianceReport(
            generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            disclaimer=DISCLAIMER,
            controls=controls,
            gaps=self._gaps(),
        )

    def _gaps(self) -> list:
        gaps = list(OUT_OF_SCOPE_CRITERIA)

        # The integrity asymmetry an auditor will find on their own.
        gaps.append(
            "audit log is append-only but not tamper-evident: unlike the forensic vault "
            "it has no hash chain, so an administrator could edit it undetected"
        )

        custody_problems = self.vault.verify_chain()
        if custody_problems:
            gaps.append(f"forensic custody chain does not verify: {custody_problems[0]}")

        policy_state = self.policy.load()
        if policy_state is None:
            gaps.append(
                "no regeneration cadence configured: recovery is manual-trigger only, "
                "which weakens any availability commitment based on scheduled rebuilds"
            )

        gaps.append(
            "report covers all audit-log history, not a defined observation period; "
            "an audit requires evidence scoped to a specific window"
        )
        return gaps

    def write(self, path: Path) -> ComplianceReport:
        report = self.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report.to_json())
        return report
