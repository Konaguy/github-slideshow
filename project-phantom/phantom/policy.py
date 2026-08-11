"""Regeneration policy: scheduled/ephemeral regeneration, independent of
attack detection.

Charter §5.C: "Two modes: attack-triggered and scheduled ephemeral rebuilds
(daily/per-session)." §6 Phase 2: "Scheduled regeneration ships before
automated detection. Moving-target value doesn't depend on detection
accuracy." Product tier: "Phantom Ephemeral -- Scheduled regeneration
(daily or per-session) regardless of attack status."

This module only tracks *when* a scheduled regeneration is due; the
orchestrator is what actually triggers it (see
`PhantomInstance.scheduled_check` / `.session_start`).
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

VALID_CADENCES = {"daily", "per_session"}
DEFAULT_DAILY_INTERVAL_SECONDS = 24 * 60 * 60


@dataclass
class PolicyState:
    cadence: str
    interval_seconds: int
    last_regenerated_at: Optional[float]


class RegenerationPolicy:
    def __init__(self, path: Path):
        self.path = path

    def load(self) -> Optional[PolicyState]:
        if not self.path.exists():
            return None
        return PolicyState(**json.loads(self.path.read_text()))

    def set(self, cadence: str, interval_seconds: int = DEFAULT_DAILY_INTERVAL_SECONDS) -> PolicyState:
        if cadence not in VALID_CADENCES:
            raise ValueError(f"cadence must be one of {sorted(VALID_CADENCES)}, got {cadence!r}")
        existing = self.load()
        state = PolicyState(
            cadence=cadence,
            interval_seconds=interval_seconds,
            last_regenerated_at=existing.last_regenerated_at if existing else None,
        )
        self._save(state)
        return state

    def mark_regenerated(self, at: Optional[float] = None) -> None:
        state = self.load()
        if state is None:
            return
        state.last_regenerated_at = at if at is not None else time.time()
        self._save(state)

    def is_daily_due(self, now: Optional[float] = None) -> bool:
        state = self.load()
        if state is None or state.cadence != "daily":
            return False
        now = now if now is not None else time.time()
        if state.last_regenerated_at is None:
            return True
        return (now - state.last_regenerated_at) >= state.interval_seconds

    def _save(self, state: PolicyState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(asdict(state), indent=2))
