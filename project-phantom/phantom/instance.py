"""Disposable compute instance -- the thing that gets destroyed and reborn.

Charter §1.1 step 4: "The compromised desktop, server, container, or
workload is treated as disposable... Phantom removes the attacker's
foothold by terminating the environment." §5.K later abstracts this behind
a portable, provider-agnostic driver so the same regeneration policy works
across KVM/QEMU and every target cloud.

This MVP has exactly one driver -- a local workspace directory -- but the
orchestrator only talks to the `InstanceDriver` interface below, so a
Phase 3 KVM/QEMU or cloud driver can be dropped in without touching the
regeneration logic in orchestrator.py.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Protocol


class InstanceDriver(Protocol):
    def exists(self) -> bool: ...
    def destroy(self) -> None: ...
    def spawn_from_baseline(self, baseline_dir: Path, instance_id: str) -> None: ...
    @property
    def data_dir(self) -> Path: ...


class LocalWorkspaceInstance:
    """Phase 1 driver: an instance is just a directory on local disk."""

    def __init__(self, root: Path):
        self.root = root
        self._data_dir = root / "data"
        self.marker = root / ".instance.json"

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    def exists(self) -> bool:
        return self.marker.exists()

    def destroy(self) -> None:
        if self.root.exists():
            shutil.rmtree(self.root)

    def spawn_from_baseline(self, baseline_dir: Path, instance_id: str) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for item in baseline_dir.iterdir():
            if item.name == "baseline.manifest.json":
                continue
            dest = self.root / item.name
            if item.is_dir():
                shutil.copytree(item, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dest)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self.marker.write_text(json.dumps({
            "instance_id": instance_id,
            "spawned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, indent=2))

    def info(self) -> dict:
        if not self.exists():
            return {}
        return json.loads(self.marker.read_text())
