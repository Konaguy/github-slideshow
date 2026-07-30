"""Thin, content-addressed snapshot engine.

Charter §5.A: "Block-level thin delta snapshots (30-60s intervals)."

This MVP snapshots at file granularity rather than block granularity, but
keeps the property that matters for the demo: only *changed* content is
ever written to the store. Each file's bytes are addressed by their sha256
hash, so an unchanged file across two snapshots costs zero additional
storage (dedup), and a snapshot's manifest is just a small pointer file
mapping relpath -> content hash.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class Snapshot:
    snapshot_id: str
    taken_at: str
    parent_id: Optional[str]
    files: dict  # relpath -> content hash


class SnapshotEngine:
    """Snapshots a data directory into a content-addressed store.

    store_dir layout:
      objects/<sha256>            content blobs (dedup'd across all snapshots)
      snapshots/<snapshot_id>.json  manifests (relpath -> hash), newest last
    """

    def __init__(self, store_dir: Path):
        self.store_dir = store_dir
        self.objects_dir = store_dir / "objects"
        self.snapshots_dir = store_dir / "snapshots"
        self.objects_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def take_snapshot(self, data_dir: Path) -> Snapshot:
        parent = self.latest_snapshot()
        files = {}
        for path in sorted(p for p in data_dir.rglob("*") if p.is_file()):
            relpath = str(path.relative_to(data_dir))
            content = path.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            blob_path = self.objects_dir / digest
            if not blob_path.exists():  # new content only -- this is the "thin" part
                blob_path.write_bytes(content)
            files[relpath] = digest

        snapshot_id = time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime()) + f"-{len(files):04d}"
        snapshot = Snapshot(
            snapshot_id=snapshot_id,
            taken_at=_now(),
            parent_id=parent.snapshot_id if parent else None,
            files=files,
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
        }, indent=2))

    def list_snapshots(self) -> list[Snapshot]:
        result = []
        for path in sorted(self.snapshots_dir.glob("*.json")):
            data = json.loads(path.read_text())
            result.append(Snapshot(**data))
        return result

    def latest_snapshot(self) -> Optional[Snapshot]:
        snapshots = self.list_snapshots()
        return snapshots[-1] if snapshots else None

    def read_blob(self, digest: str) -> bytes:
        return (self.objects_dir / digest).read_bytes()

    def restore(self, snapshot: Snapshot, dest_dir: Path) -> None:
        """Reconstruct every file in `snapshot` under dest_dir from the object store."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        for relpath, digest in snapshot.files.items():
            target = dest_dir / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(self.read_blob(digest))


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
