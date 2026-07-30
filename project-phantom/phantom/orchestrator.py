"""Ties baseline + snapshot + backup + sanitize + policy + detection +
forensics + fleet intel + instance into the observe -> decide -> preserve ->
destroy -> regenerate -> restore -> harden loop described in charter §1.1.

`PhantomInstance` is the single facade the CLI talks to.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import time
from pathlib import Path
from typing import Optional

from phantom import baseline as baseline_mod
from phantom.backup_store import BackupStore
from phantom.detection import DetectionEngine
from phantom.fleet import ThreatIntelFeed
from phantom.forensics import ForensicVault
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
    def __init__(self, root: Path, feed_path: Optional[Path] = None, instance_id: str = "phantom-vm-0"):
        self.root = root
        self.instance_id = instance_id
        self.baseline_dir = root / "baseline"
        self.instance = LocalWorkspaceInstance(root / "instance")
        self.backup = BackupStore(root / "backups")
        self.audit = AuditLog(root / "audit.log")
        self.blocklist = Blocklist(root / "known_bad_hashes.json")
        self.quarantine = QuarantineStore(root / "quarantine")
        self.policy = RegenerationPolicy(root / "policy.json")
        self.vault = ForensicVault(root / "forensic_vault")
        self.detector = DetectionEngine(read_blob=self.backup.engine.read_blob)
        # A feed outside this instance's root is the fleet-wide one; the
        # default keeps a single instance self-contained for the basic demo.
        self.feed = ThreatIntelFeed(feed_path if feed_path is not None else root / "threat_intel.jsonl")

    # -- provisioning ------------------------------------------------

    def init(self, instance_id: Optional[str] = None) -> None:
        instance_id = instance_id or self.instance_id
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

    def scheduled_check(self, now: Optional[float] = None, instance_id: Optional[str] = None):
        """Cron entrypoint for the "daily" cadence. No-op if not due yet."""
        if not self.policy.is_daily_due(now):
            return None
        report = self.regenerate(reason="scheduled: daily cadence", instance_id=instance_id)
        self.policy.mark_regenerated(now if now is not None else report.finished_at)
        return report

    def session_start(self, instance_id: Optional[str] = None):
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
        deliberately does not touch existing files -- see
        `simulate_encryption_attack` for the in-place-encryption variant.
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

    def simulate_encryption_attack(self) -> list:
        """Overwrite existing user files with high-entropy content in place.

        This is the delta shape the detection engine (§5.D) is meant to
        catch on behavioral signals alone -- mass rewrite plus an entropy
        jump -- with no known-bad hash and no suspicious filename to match
        on. Unlike `simulate_attack`, nothing here is pre-registered in the
        blocklist: detection has to earn it.

        Note the recovery story: the encrypted versions are what the *next*
        snapshot captures, so recovery depends on regenerating from the
        prior clean snapshot, not on sanitizing the current one.
        """
        import os

        encrypted = []
        for path in sorted(p for p in self.instance.data_dir.rglob("*") if p.is_file()):
            path.write_bytes(os.urandom(2048))
            encrypted.append(str(path.relative_to(self.instance.data_dir)))

        self.audit.append("encryption_attack_simulated", encrypted_files=encrypted)
        return encrypted

    # -- detection (charter §5.D) ---------------------------------------

    def detect(self, current=None):
        """Score the most recent inter-snapshot delta for behavioral drift."""
        snapshots = self.backup.engine.list_snapshots()
        if not snapshots:
            return None
        current = current if current is not None else snapshots[-1]
        index = next((i for i, s in enumerate(snapshots) if s.snapshot_id == current.snapshot_id), None)
        previous = snapshots[index - 1] if index is not None and index > 0 else None

        result = self.detector.evaluate(previous, current)
        self.audit.append(
            "detection_evaluated",
            snapshot_id=current.snapshot_id,
            score=result.score,
            anomalous=result.is_anomalous,
            signals=[s.name for s in result.signals],
        )
        return result

    def detect_and_respond(self, share_intel: bool = True):
        """Full §1.1 loop: observe -> decide -> regenerate -> harden the fleet.

        Returns (detection_result, regeneration_report). The report is None
        when the delta scored below the anomaly threshold.
        """
        result = self.detect()
        if result is None or not result.is_anomalous:
            return result, None

        # Recover from the last snapshot taken BEFORE the anomalous one --
        # the anomalous snapshot is the attacker's work, restoring it would
        # just reinstate the damage.
        snapshots = self.backup.engine.list_snapshots()
        recovery_point = snapshots[-2] if len(snapshots) >= 2 else None

        report = self.regenerate(
            reason=f"detection: behavioral drift score {result.score:.2f}",
            restore_from=recovery_point,
        )
        self._publish_indicators(share=share_intel)
        return result, report

    # -- fleet immunity (charter §5.H) ------------------------------------

    def _publish_indicators(self, share: bool = True) -> list:
        """Publish content hashes of locally-known-bad content to the fleet feed."""
        local_hashes = self.blocklist.load()
        if not local_hashes:
            return []
        fingerprint = hashlib.sha256(str(self.root).encode()).hexdigest()[:12]
        published = self.feed.publish(
            local_hashes, label="phantom.local-detection", source_fingerprint=fingerprint, share=share,
        )
        if published:
            self.audit.append("intel_published", indicator_count=len(published), shared=share)
        return published

    def pull_fleet_intel(self) -> int:
        """Fold fleet-published indicators into the local blocklist.

        This is the "herd immunity" step: an instance that was never
        attacked hardens against a payload another instance saw first.
        Returns the number of newly-learned indicators.
        """
        feed_hashes = self.feed.hashes()
        local_hashes = self.blocklist.load()
        new_hashes = feed_hashes - local_hashes
        if new_hashes:
            merged = sorted(local_hashes | new_hashes)
            self.blocklist.path.parent.mkdir(parents=True, exist_ok=True)
            self.blocklist.path.write_text(json.dumps(merged, indent=2))
            self.audit.append("fleet_intel_pulled", learned=len(new_hashes))
        return len(new_hashes)

    # -- regeneration ---------------------------------------------------

    def regenerate(self, reason: str, instance_id: Optional[str] = None,
                   restore_from=None) -> RegenerationReport:
        """`restore_from` overrides the default "latest snapshot" recovery
        point -- used when detection determines the latest snapshot itself
        captured the attack (see `detect_and_respond`).
        """
        instance_id = instance_id or self.instance_id
        started_at = time.time()
        self.audit.append("regeneration_triggered", reason=reason)

        # 1. Preserve evidence before destruction (charter §1.1 step 3), into the
        #    hash-chained forensic vault (§5.F) rather than a plain copy.
        custody_entry = self.vault.capture(self.instance.data_dir, reason=reason, custodian=instance_id)
        self.audit.append(
            "evidence_preserved",
            case_id=custody_entry.case_id,
            content_digest=custody_entry.content_digest,
            entry_hash=custody_entry.entry_hash,
        )

        # 2. Verify the baseline is still trustworthy, then destroy + respawn.
        baseline_mod.verify_baseline(self.baseline_dir)
        self.instance.destroy()
        self.instance.spawn_from_baseline(self.baseline_dir, instance_id)
        self.audit.append("instance_regenerated", instance_id=instance_id)

        # 3. Restore only sanitized data (charter §1.1 step 6), reading through
        #    the multi-region store so a single provider outage doesn't block
        #    recovery (charter §6 Phase 2 "multi-region failover").
        latest = restore_from if restore_from is not None else self.backup.rapid_retrieve()
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
            evidence_path=str((self.vault.root / custody_entry.case_id).relative_to(self.root)),
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
        custody_problems = self.vault.verify_chain()
        return {
            "instance": self.instance.info(),
            "snapshot_count": len(snapshots),
            "latest_snapshot": snapshots[-1].snapshot_id if snapshots else None,
            "providers": self.backup.provider_status(),
            "policy": policy_state.__dict__ if policy_state else None,
            "forensic_vault": {
                "case_count": len(self.vault.entries()),
                "chain_intact": not custody_problems,
                "problems": custody_problems,
            },
            "threat_intel": {
                "known_bad_hashes": len(self.blocklist.load()),
                "feed_indicators": len(self.feed.indicators()),
            },
            "recent_audit_events": self.audit.tail(10),
        }


def _parse_ts(ts: str) -> float:
    return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
