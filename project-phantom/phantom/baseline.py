"""Hardened immutable baseline image.

Charter §1.1 step 5: "A clean instance is spawned from a hardened immutable
baseline with approved patches, configurations, identity controls, and
security hooks already applied." In this MVP the baseline is just a
directory of files plus a manifest of their hashes; `verify()` is the
"immutable" guarantee — any drift from the manifest is treated as a
corrupted baseline, never silently trusted.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BaselineInfo:
    version: str
    created_at: str
    files: dict  # relpath -> sha256


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _manifest_path(baseline_dir: Path) -> Path:
    return baseline_dir / "baseline.manifest.json"


def create_baseline(baseline_dir: Path, files: dict, version: str = "1.0.0") -> BaselineInfo:
    """Write `files` (relpath -> content) into baseline_dir and seal a manifest."""
    baseline_dir.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for relpath, content in files.items():
        target = baseline_dir / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        hashes[relpath] = _hash_file(target)

    info = BaselineInfo(version=version, created_at=_now(), files=hashes)
    _manifest_path(baseline_dir).write_text(
        json.dumps({"version": info.version, "created_at": info.created_at, "files": info.files}, indent=2)
    )
    return info


def load_manifest(baseline_dir: Path) -> BaselineInfo:
    data = json.loads(_manifest_path(baseline_dir).read_text())
    return BaselineInfo(version=data["version"], created_at=data["created_at"], files=data["files"])


def verify_baseline(baseline_dir: Path) -> None:
    """Raise BaselineIntegrityError if any manifest file is missing or has drifted."""
    manifest = load_manifest(baseline_dir)
    for relpath, expected_hash in manifest.files.items():
        path = baseline_dir / relpath
        if not path.exists():
            raise BaselineIntegrityError(f"baseline file missing: {relpath}")
        actual_hash = _hash_file(path)
        if actual_hash != expected_hash:
            raise BaselineIntegrityError(
                f"baseline drift detected in {relpath}: expected {expected_hash}, got {actual_hash}"
            )


class BaselineIntegrityError(RuntimeError):
    pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
