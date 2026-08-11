"""Cloud backup & versioning (§5.B) built on the multi-region abstraction (§5.K "initial", §6 Phase 2).

Phase 1 replicated blobs to a second local directory as a stand-in for
multi-region storage. This promotes that into named, independently
addressed providers (still local-disk-backed -- no real cloud credentials
are available here) standing in for AWS/Azure/private-cloud, fanned out to
on every write via `MultiRegionStore`, with failover on read baked into
`SnapshotEngine.read_blob` / `restore`. Versioning and dedup fall out of
`SnapshotEngine`'s content addressing.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from phantom.snapshot import SnapshotEngine
from phantom.storage import LocalDiskProvider, MultiRegionStore

DEFAULT_PROVIDER_NAMES = ["aws-us-east-1", "azure-westus", "private-cloud"]


class BackupStore:
    def __init__(self, root: Path, provider_names: Optional[list] = None):
        self.root = root
        names = provider_names if provider_names is not None else DEFAULT_PROVIDER_NAMES
        self.providers = [LocalDiskProvider(name, root / "providers" / name) for name in names]
        self.store = MultiRegionStore(self.providers)
        self.engine = SnapshotEngine(root / "control", self.store)

    def rapid_retrieve(self, snapshot_id: Optional[str] = None):
        """Fetch a snapshot by id, or the latest if unspecified."""
        snapshots = self.engine.list_snapshots()
        if not snapshots:
            return None
        if snapshot_id is None:
            return snapshots[-1]
        for snap in snapshots:
            if snap.snapshot_id == snapshot_id:
                return snap
        raise KeyError(f"no such snapshot: {snapshot_id}")

    def provider_status(self) -> dict:
        return {
            provider.name: "available" if provider.is_available() else "unavailable (simulated outage)"
            for provider in self.providers
        }

    def set_outage(self, provider_name: str, down: bool) -> None:
        for provider in self.providers:
            if provider.name == provider_name:
                provider.set_outage(down)
                return
        raise KeyError(f"no such provider: {provider_name}")
