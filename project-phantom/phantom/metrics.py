"""RTO/RPO measurement and audit logging.

Charter §4 targets this prototype checks itself against:
  RTO (Recovery Time Objective) < 5 minutes
  RPO (Recovery Point Objective) < 1 minute

Charter §5.J calls for "audit logging" as part of Enterprise Integration;
`AuditLog` here is a minimal JSON-lines stand-in for that.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

RTO_TARGET_SECONDS = 5 * 60
RPO_TARGET_SECONDS = 60


@dataclass
class RegenerationReport:
    reason: str
    started_at: float
    finished_at: float
    last_snapshot_at: float
    files_restored: int
    files_quarantined: int
    evidence_path: str

    @property
    def rto_seconds(self) -> float:
        return self.finished_at - self.started_at

    @property
    def rpo_seconds(self) -> float:
        """Data lost = time between the last snapshot and the moment we destroyed the instance."""
        return max(0.0, self.started_at - self.last_snapshot_at)

    @property
    def rto_pass(self) -> bool:
        return self.rto_seconds < RTO_TARGET_SECONDS

    @property
    def rpo_pass(self) -> bool:
        return self.rpo_seconds < RPO_TARGET_SECONDS

    def summary(self) -> str:
        lines = [
            f"Regeneration complete: reason={self.reason}",
            f"  RTO: {self.rto_seconds:.3f}s  (target < {RTO_TARGET_SECONDS}s)   "
            f"{'PASS' if self.rto_pass else 'FAIL'}",
            f"  RPO: {self.rpo_seconds:.3f}s  (target < {RPO_TARGET_SECONDS}s)    "
            f"{'PASS' if self.rpo_pass else 'FAIL'}",
            f"  files restored: {self.files_restored}   quarantined: {self.files_quarantined}",
            f"  evidence preserved: {self.evidence_path}",
        ]
        return "\n".join(lines)


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: str, **fields) -> None:
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields}
        with self.path.open("a") as fh:
            fh.write(json.dumps(record) + "\n")

    def tail(self, n: int = 10) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text().splitlines()
        return [json.loads(line) for line in lines[-n:]]
