"""Cloud backup & versioning stand-in.

Charter §5.B: "Multi-region immutable storage, deduplication, rapid
retrieval." Real multi-region object storage is out of reach for this MVP,
so `replicate()` mirrors the snapshot store into a second local "region"
directory after every snapshot. Versioning and dedup already fall out of
`SnapshotEngine`'s content-addressing (§5.A) -- this module only adds the
replication step and a rapid-retrieval helper.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from phantom.snapshot import SnapshotEngine


class BackupStore:
    def __init__(self, primary_dir: Path, replica_dir: Path):
        self.primary = SnapshotEngine(primary_dir)
        self.replica_dir = replica_dir

    def replicate(self) -> None:
        """Mirror the primary store to the replica region. Immutable: only adds objects."""
        self.replica_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.primary.store_dir, self.replica_dir, dirs_exist_ok=True)

    def rapid_retrieve(self, snapshot_id: str | None = None):
        """Fetch a snapshot by id, or the latest if unspecified."""
        snapshots = self.primary.list_snapshots()
        if not snapshots:
            return None
        if snapshot_id is None:
            return snapshots[-1]
        for snap in snapshots:
            if snap.snapshot_id == snapshot_id:
                return snap
        raise KeyError(f"no such snapshot: {snapshot_id}")
