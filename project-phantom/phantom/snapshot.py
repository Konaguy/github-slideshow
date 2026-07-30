"""Thin, content-addressed snapshot engine.

Charter §5.A: "Block-level thin delta snapshots (30-60s intervals)."

This MVP snapshots at file granularity rather than block granularity, but
keeps the property that matters for the demo: only *changed* content is
ever written to storage. Each file's bytes are addressed by their sha256
hash, so an unchanged file across two snapshots costs zero additional
writes (dedup), and a snapshot's manifest is just a small pointer file
mapping relpath -> content hash.

Blob storage itself is delegated to a `MultiRegionStore` (phantom/storage.py)
rather than a single local directory, so snapshots are replicated across
providers and survive a single provider outage (charter §6 Phase 2:
"multi-region failover"). Manifests -- small pointer files, not bulk data
-- stay in a single local control directory for this MVP.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from phantom.storage import MultiRegionStore


INTERVAL = "interval"
POST_REGENERATION = "post_regeneration"


@dataclass
class Snapshot:
    snapshot_id: str
    taken_at: str
    parent_id: Optional[str]
    files: dict  # relpath -> content hash
    # "interval" = an ordinary periodic capture. "post_regeneration" = the
    # clean state right after a rebuild. The distinction matters to the
    # detection engine: the delta across a rebuild is Phantom's own
    # recovery, not attacker activity, and scoring it as drift would have
    # the product treating its own remediation as an incident.
    kind: str = INTERVAL


class SnapshotEngine:
    """Snapshots a data directory, storing manifests locally and blob
    content in `store` (a MultiRegionStore).

    control_dir layout:
      snapshots/<snapshot_id>.json  manifests (relpath -> hash), newest last
    """

    def __init__(self, control_dir: Path, store: MultiRegionStore):
        self.control_dir = control_dir
        self.snapshots_dir = control_dir / "snapshots"
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self.store = store

    def take_snapshot(self, data_dir: Path, kind: str = INTERVAL) -> Snapshot:
        # Only the chain length and the parent's *id* are needed here, and
        # both come from the manifest filenames -- so this deliberately
        # does not call list_snapshots(), which parses every manifest in
        # the chain. That parse is O(chain_length x file_count) and, since
        # a snapshot is taken every 30-60s, it came to dominate snapshot
        # cost within hours of operation (measured in phantom/benchmark.py:
        # 0.9ms at chain length 1, 116ms at 200, still climbing).
        existing_paths = self._manifest_paths()
        parent_id = existing_paths[-1].stem if existing_paths else None
        files = {}
        for path in sorted(p for p in data_dir.rglob("*") if p.is_file()):
            relpath = str(path.relative_to(data_dir))
            content = path.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            if not self.store.has_any(digest):  # new content only -- this is the "thin" part
                self.store.put(digest, content)
            files[relpath] = digest

        # The sequence number, not the timestamp, is what makes this unique:
        # snapshots at 30-60s intervals can easily land in the same second,
        # and a colliding id would silently overwrite the previous manifest.
        # Zero-padded so lexical sort matches chronological order.
        snapshot_id = time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime()) + f"-{len(existing_paths):06d}"
        snapshot = Snapshot(
            snapshot_id=snapshot_id,
            taken_at=_now(),
            parent_id=parent_id,
            files=files,
            kind=kind,
        )
        self._write_manifest(snapshot)
        return snapshot

    def _write_manifest(self, snapshot: Snapshot) -> None:
        path = self.snapshots_dir / f"{snapshot.snapshot_id}.json"
        path.write_text(json.dumps({
            "snapshot_id": snapshot.snapshot_id,
            "taken_at": snapshot.taken_at,
            "parent_id": snapshot.parent_id,
            "files": snapshot.files,
            "kind": snapshot.kind,
        }, indent=2))

    def _manifest_paths(self) -> list:
        """Manifest files, oldest first. The zero-padded sequence in each
        snapshot id makes lexical order chronological. Filenames only --
        no parsing, so this stays cheap as the chain grows."""
        return sorted(self.snapshots_dir.glob("*.json"))

    def _read_manifest(self, path: Path) -> Snapshot:
        return Snapshot(**json.loads(path.read_text()))

    def list_snapshots(self) -> list:
        """Every snapshot, fully parsed. Callers that only need the newest
        one should use latest_snapshot() -- this parses the whole chain."""
        return [self._read_manifest(path) for path in self._manifest_paths()]

    def latest_snapshot(self) -> Optional[Snapshot]:
        paths = self._manifest_paths()
        return self._read_manifest(paths[-1]) if paths else None

    def read_blob(self, digest: str) -> bytes:
        content, _provider_name = self.store.get(digest)
        return content

    def restore(self, snapshot: Snapshot, dest_dir: Path) -> None:
        """Reconstruct every file in `snapshot` under dest_dir from storage."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        for relpath, digest in snapshot.files.items():
            target = dest_dir / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(self.read_blob(digest))


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
