"""Local-workspace driver for the provider-agnostic contract.

The same "an instance is a directory" model `phantom/instance.py` uses,
re-expressed against `ComputeDriver` so the conformance suite can hold it
to the same behaviour as a cloud driver. It exists to prove the contract
is genuinely provider-agnostic -- a contract only one implementation
satisfies has not been tested for portability.

`phantom/instance.py` is untouched; the orchestrator still uses it. Wiring
the orchestrator onto this contract is a separate change with a real blast
radius across the existing suite.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from phantom.drivers.base import (
    PHANTOM_INSTANCE_TAG,
    PHANTOM_MANAGED_TAG,
    PHANTOM_MANAGED_VALUE,
    DestroyRefused,
    InstanceHandle,
)

_MARKER = ".phantom-instance.json"


class LocalDriver:
    """Instances are directories under `root`."""

    provider = "local"

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # -- lifecycle -----------------------------------------------------------

    def spawn(self, baseline_ref: str, instance_id: str) -> InstanceHandle:
        native_id = f"{instance_id}-{int(time.time() * 1_000_000)}"
        target = self.root / native_id
        shutil.copytree(Path(baseline_ref), target / "data", dirs_exist_ok=True)

        # The tag is what makes this instance destroyable. Written last so a
        # half-created instance is never eligible for destruction.
        (target / _MARKER).write_text(json.dumps({
            PHANTOM_MANAGED_TAG: PHANTOM_MANAGED_VALUE,
            PHANTOM_INSTANCE_TAG: instance_id,
        }, indent=2))
        return InstanceHandle(provider=self.provider, native_id=native_id, instance_id=instance_id)

    def exists(self, handle: InstanceHandle) -> bool:
        return (self.root / handle.native_id).is_dir()

    def destroy(self, handle: InstanceHandle) -> None:
        target = self.root / handle.native_id
        if not self._is_phantom_managed(target):
            raise DestroyRefused(
                f"refusing to destroy {handle.native_id!r}: missing "
                f"{PHANTOM_MANAGED_TAG}={PHANTOM_MANAGED_VALUE}"
            )
        shutil.rmtree(target)

    def _is_phantom_managed(self, target: Path) -> bool:
        marker = target / _MARKER
        if not marker.exists():
            return False
        try:
            tags = json.loads(marker.read_text())
        except (json.JSONDecodeError, OSError):
            return False
        return tags.get(PHANTOM_MANAGED_TAG) == PHANTOM_MANAGED_VALUE

    # -- data movement -------------------------------------------------------

    def snapshot(self, handle: InstanceHandle) -> str:
        snap_id = f"{handle.native_id}-snap-{int(time.time() * 1_000_000)}"
        dest = self.root / ".snapshots" / snap_id
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.root / handle.native_id / "data", dest, dirs_exist_ok=True)
        return snap_id

    def restore(self, handle: InstanceHandle, snapshot_ref: str) -> None:
        source = self.root / ".snapshots" / snapshot_ref
        data_dir = self.root / handle.native_id / "data"
        if data_dir.exists():
            shutil.rmtree(data_dir)
        shutil.copytree(source, data_dir)

    # -- helper for tests / callers -----------------------------------------

    def data_path(self, handle: InstanceHandle) -> Path:
        """Local-only convenience. Deliberately NOT on the contract -- a
        remote VM has no local path, and putting this on the interface is
        exactly the mistake the old InstanceDriver made."""
        return self.root / handle.native_id / "data"
