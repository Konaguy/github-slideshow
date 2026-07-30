"""Ties baseline + snapshot + backup + sanitize + policy + instance into the
observe -> preserve -> destroy -> regenerate -> restore -> harden loop
described in charter §1.1.

`PhantomInstance` is the single facade the CLI talks to.
"""
from __future__ import annotations

import calendar
import shutil
import time
from pathlib import Path
from typing import Optional

from phantom import baseline as baseline_mod
from phantom.backup_store import BackupStore
from phantom.instance import LocalWorkspaceInstance
from phantom.metrics import AuditLog, RegenerationReport
from phantom.policy import RegenerationPolicy
from phantom.sanitize import Blocklist, QuarantineStore, scan
from phantom.storage import ProviderUnavailable

DEFAULT_BASELINE_FILES = {
    "etc/security-policy.conf": "hardened=true\npatch-level=current\n",
    "etc/motd": "Project Phantom -- hardened baseline instance\n",
}


class PhantomInstance:
    def __init__(self, root: Path):
        self.root = root
        self.baseline_dir = root / "baseline"
        self.instance = LocalWorkspaceInstance(root / "instance")
        self.backup = BackupStore(root / "backups")
        self.evidence_dir = root / "evidence"
        self.audit = AuditLog(root / "audit.log")
        self.blocklist = Blocklist(root / "known_bad_hashes.json")
        self.quarantine = QuarantineStore(root / "quarantine")
        self.policy = RegenerationPolicy(root / "policy.json")

    # -- provisioning ------------------------------------------------

    def init(self, instance_id: str = "phantom-vm-0") -> None:
        baseline_mod.create_baseline(self.baseline_dir, DEFAULT_BASELINE_FILES)
        self.audit.append("baseline_created", version="1.0.0")

        self.instance.destroy()
        self.instance.spawn_from_baseline(self.baseline_dir, instance_id)
        self.audit.append("instance_spawned", instance_id=instance_id, reason="init")

    # -- policy ------------------------------------------------------

    def set_policy(self, cadence: str, interval_seconds: Optional[int] = None):
        kwargs = {} if interval_seconds is None else {"interval_seconds": interval_seconds}
        state = self.policy.set(cadence, **kwargs)
        self.audit.append("policy_set", cadence=state.cadence, interval_seconds=state.interval_seconds)
        return state

    def scheduled_check(self, now: Optional[float] = None, instance_id: str = "phantom-vm-0"):
        """Cron entrypoint for the "daily" cadence. No-op if not due yet."""
        if not self.policy.is_daily_due(now):
            return None
        report = self.regenerate(reason="scheduled: daily cadence", instance_id=instance_id)
        self.policy.mark_regenerated(now if now is not None else report.finished_at)
        return report

    def session_start(self, instance_id: str = "phantom-vm-0"):
        """Simulates a user starting a session. Regenerates first if the
        policy cadence is "per_session" -- moving-target defense that
        doesn't depend on any attack having been detected.
        """
        state = self.policy.load()
        if state is not None and state.cadence == "per_session":
            report = self.regenerate(reason="scheduled: per-session cadence", instance_id=instance_id)
            self.policy.mark_regenerated(report.finished_at)
            self.audit.append("session_started", regenerated=True)
            return report
        self.audit.append("session_started", regenerated=False)
        return None

    # -- normal operation ---------------------------------------------

    def write_user_file(self, relpath: str, content: str) -> None:
        target = self.instance.data_dir / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def take_snapshot(self):
        snap = self.backup.engine.take_snapshot(self.instance.data_dir)
        self.audit.append("snapshot_taken", snapshot_id=snap.snapshot_id, file_count=len(snap.files))
        return snap

    # -- attack simulation (for the demo only) -------------------------

    def simulate_attack(self) -> list:
        """Plant dormant-malware-style artifacts alongside legitimate user data.

        Charter §9 risk register: "Dormant malware in user data re-infects
        spawns." The scenario this exercises is malware landing *among* a
        user's files (a dropped ransom note, a payload disguised as a
        document) that would get scooped up by the next snapshot and, if
        restored blindly, re-infect the freshly regenerated instance. It
        deliberately does not touch existing legitimate files -- there is
        no detection/recovery story for already-encrypted data in this
        prototype; that is a Phase 3 problem (§5.D AI-vs-AI Detection Engine).
        """
        planted = []

        note_path = "RANSOM_NOTE_README.txt"
        note_content = "Your files are encrypted. Pay to recover them.\n"
        self.blocklist.register(note_content.encode())
        self.write_user_file(note_path, note_content)
        planted.append(note_path)

        payload_path = "invoice.pdf.exe"
        payload_content = "MZ-fake-payload-bytes"
        self.blocklist.register(payload_content.encode())
        self.write_user_file(payload_path, payload_content)
        planted.append(payload_path)

        self.audit.append("attack_simulated", planted_files=planted)
        return planted

    # -- regeneration ---------------------------------------------------

    def regenerate(self, reason: str, instance_id: str = "phantom-vm-0") -> RegenerationReport:
        started_at = time.time()
        self.audit.append("regeneration_triggered", reason=reason)

        # 1. Preserve evidence before destruction (charter §1.1 step 3).
        evidence_path = self.evidence_dir / time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime())
        if self.instance.data_dir.exists():
            shutil.copytree(self.instance.data_dir, evidence_path / "data", dirs_exist_ok=True)
        self.audit.append("evidence_preserved", path=str(evidence_path))

        # 2. Verify the baseline is still trustworthy, then destroy + respawn.
        baseline_mod.verify_baseline(self.baseline_dir)
        self.instance.destroy()
        self.instance.spawn_from_baseline(self.baseline_dir, instance_id)
        self.audit.append("instance_regenerated", instance_id=instance_id)

        # 3. Restore only sanitized data from the latest snapshot (charter §1.1 step 6),
        #    reading through the multi-region store so a single provider outage
        #    doesn't block recovery (charter §6 Phase 2 "multi-region failover").
        latest = self.backup.rapid_retrieve()
        files_restored = 0
        files_quarantined = 0
        last_snapshot_at = started_at
        quarantine_batch_path = None
        if latest is not None:
            last_snapshot_at = _parse_ts(latest.taken_at)
            raw_files = {}
            unrecoverable = []
            for relpath, digest in latest.files.items():
                try:
                    raw_files[relpath] = self.backup.engine.read_blob(digest)
                except ProviderUnavailable:
                    unrecoverable.append(relpath)
            if unrecoverable:
                self.audit.append("restore_degraded", unrecoverable_files=unrecoverable)

            result = scan(raw_files, known_bad_hashes=self.blocklist.load())
            for relpath in result.clean:
                target = self.instance.data_dir / relpath
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw_files[relpath])
            files_restored = len(result.clean)
            files_quarantined = len(result.quarantined)

            if result.quarantined:
                batch_id = time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime())
                quarantine_dir = self.quarantine.persist(batch_id, raw_files, result)
                quarantine_batch_path = str(quarantine_dir.relative_to(self.root))

            self.audit.append(
                "data_restored",
                snapshot_id=latest.snapshot_id,
                restored=files_restored,
                quarantined=files_quarantined,
                quarantine_reasons={
                    relpath: [f"{f.rule}:{f.severity}:{f.reason}" for f in findings]
                    for relpath, findings in result.quarantined.items()
                },
                quarantine_path=quarantine_batch_path,
            )

        finished_at = time.time()
        report = RegenerationReport(
            reason=reason,
            started_at=started_at,
            finished_at=finished_at,
            last_snapshot_at=last_snapshot_at,
            files_restored=files_restored,
            files_quarantined=files_quarantined,
            evidence_path=str(evidence_path.relative_to(self.root)),
        )
        self.audit.append(
            "regeneration_complete",
            rto_seconds=report.rto_seconds,
            rpo_seconds=report.rpo_seconds,
            rto_pass=report.rto_pass,
            rpo_pass=report.rpo_pass,
        )
        return report

    # -- status -----------------------------------------------------------

    def status(self) -> dict:
        snapshots = self.backup.engine.list_snapshots()
        policy_state = self.policy.load()
        return {
            "instance": self.instance.info(),
            "snapshot_count": len(snapshots),
            "latest_snapshot": snapshots[-1].snapshot_id if snapshots else None,
            "providers": self.backup.provider_status(),
            "policy": policy_state.__dict__ if policy_state else None,
            "recent_audit_events": self.audit.tail(10),
        }


def _parse_ts(ts: str) -> float:
    return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
