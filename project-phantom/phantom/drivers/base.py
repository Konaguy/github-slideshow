"""Provider-agnostic compute driver contract.

## Why this exists

`phantom/instance.py`'s `InstanceDriver` has been described since Phase 1
as "the seam cloud drivers plug into." It is not, and cannot be:

    def spawn_from_baseline(self, baseline_dir: Path, ...) -> None
    @property
    def data_dir(self) -> Path

Both signatures are filesystem-shaped. A cloud baseline is an AMI id or a
Compute Gallery reference, not a `Path`; a remote VM has no local
`data_dir`. Implementing that Protocol for EC2 would require lying about
the return types.

This module is the contract that *can* express both. The differences from
the old one:

  * **References, not paths.** A baseline is an opaque `str` the driver
    knows how to interpret -- a directory for local, an AMI id for EC2.
  * **Handles, not implicit singletons.** `spawn` returns an
    `InstanceHandle` identifying what was created; every other call takes
    one. A driver can manage many instances.
  * **Snapshot/restore are driver operations.** Data movement on a real VM
    happens from *outside* the guest (EBS / Managed Disk snapshots), not by
    reading a local directory. This is also what makes §5.A's "block-level"
    real: the provider does incremental block tracking, which is the fix
    for the 12,288x write amplification `phantom/benchmark.py` measured.

## The destroy guard is the point

Phantom's core loop is *programmatically terminating machines on a timer*.
A scheduler bug here does not produce a wrong answer, it deletes
infrastructure. So `destroy()` is required to verify the target carries
Phantom's own marker before acting, and to raise `DestroyRefused`
otherwise.

That check is deliberately redundant with cloud IAM policy. IAM is the
control that should stop this, but IAM policies are written by humans
under time pressure and a tag condition is easy to get subtly wrong. This
guard costs one API call and means a mis-scoped policy is not the only
thing standing between a bug and someone's fleet.

## Conformance

`ComputeDriverConformance` is a pytest mixin. Any driver claiming to
implement this contract should subclass it and supply `make_driver()`;
the shared tests then hold every implementation to the same observable
behaviour, so a second provider is cheap to add and hard to get subtly
wrong.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

#: Marker every Phantom-managed instance carries. `destroy` refuses to act
#: on anything lacking it.
PHANTOM_MANAGED_TAG = "phantom:managed"
PHANTOM_MANAGED_VALUE = "true"
PHANTOM_INSTANCE_TAG = "phantom:instance-id"


class DriverError(RuntimeError):
    """Base class for driver failures."""


class DestroyRefused(DriverError):
    """Raised when destroy() is asked to terminate something that is not
    demonstrably Phantom-managed. This is a safety stop, not a
    recoverable condition -- treat it as a bug in whatever computed the
    target, never as something to retry or force past."""


class InstanceNotFound(DriverError):
    pass


@dataclass(frozen=True)
class InstanceHandle:
    """Identifies one spawned instance, whatever the provider."""

    provider: str
    native_id: str  # i-0abc… for EC2; a directory name for local
    instance_id: str  # Phantom's own logical id
    metadata: dict = field(default_factory=dict)


@runtime_checkable
class ComputeDriver(Protocol):
    """What Phantom needs from a compute provider.

    Implementations must be safe to call from a scheduler: `destroy` is
    guarded (see DestroyRefused), and `exists` must not raise for an
    instance that is simply gone.
    """

    provider: str

    def spawn(self, baseline_ref: str, instance_id: str) -> InstanceHandle:
        """Create an instance from a hardened baseline, tagged as Phantom-managed."""
        ...

    def exists(self, handle: InstanceHandle) -> bool:
        """True if the instance is present. Must not raise when it is gone."""
        ...

    def destroy(self, handle: InstanceHandle) -> None:
        """Terminate the instance. MUST raise DestroyRefused if the target
        does not carry the Phantom-managed marker."""
        ...

    def snapshot(self, handle: InstanceHandle) -> str:
        """Capture instance data, returning an opaque snapshot reference."""
        ...

    def restore(self, handle: InstanceHandle, snapshot_ref: str) -> None:
        """Replace the instance's data with the contents of a snapshot."""
        ...


# -- Shared conformance suite -------------------------------------------------

class ComputeDriverConformance:
    """Behaviour every ComputeDriver must exhibit.

    Subclass in a test module and implement `make_driver` (and
    `make_baseline`). Keeping these tests in one place is what makes the
    second provider cheap: a new driver inherits the full behavioural
    spec instead of re-deriving it, and divergence shows up as a failure
    rather than as a surprise in production.
    """

    def make_driver(self):  # pragma: no cover - supplied by subclass
        raise NotImplementedError

    def make_baseline(self, driver) -> str:  # pragma: no cover
        raise NotImplementedError

    def make_foreign_handle(self, driver) -> InstanceHandle:  # pragma: no cover
        """A handle pointing at something NOT Phantom-managed."""
        raise NotImplementedError

    # -- lifecycle -----------------------------------------------------------

    def test_spawn_returns_a_usable_handle(self):
        driver = self.make_driver()
        handle = driver.spawn(self.make_baseline(driver), "vm-conformance-1")

        assert handle.provider == driver.provider
        assert handle.instance_id == "vm-conformance-1"
        assert handle.native_id
        assert driver.exists(handle)

    def test_destroy_removes_the_instance(self):
        driver = self.make_driver()
        handle = driver.spawn(self.make_baseline(driver), "vm-conformance-2")

        driver.destroy(handle)

        assert not driver.exists(handle)

    def test_exists_is_false_for_a_destroyed_instance_and_does_not_raise(self):
        driver = self.make_driver()
        handle = driver.spawn(self.make_baseline(driver), "vm-conformance-3")
        driver.destroy(handle)

        assert driver.exists(handle) is False  # must not raise

    def test_spawning_twice_yields_distinct_instances(self):
        driver = self.make_driver()
        baseline = self.make_baseline(driver)

        first = driver.spawn(baseline, "vm-a")
        second = driver.spawn(baseline, "vm-b")

        assert first.native_id != second.native_id

    # -- the safety property -------------------------------------------------

    def test_destroy_refuses_an_instance_that_is_not_phantom_managed(self):
        """The guard that stops a scheduler bug from deleting someone's
        production fleet. Redundant with IAM by design."""
        driver = self.make_driver()
        foreign = self.make_foreign_handle(driver)

        try:
            driver.destroy(foreign)
        except DestroyRefused:
            pass
        else:
            raise AssertionError("destroy() must refuse a non-Phantom-managed target")

        # And it must still be there afterwards.
        assert driver.exists(foreign)

    # -- data movement -------------------------------------------------------

    def test_snapshot_returns_a_reference_that_restore_accepts(self):
        driver = self.make_driver()
        handle = driver.spawn(self.make_baseline(driver), "vm-conformance-4")

        ref = driver.snapshot(handle)
        assert isinstance(ref, str) and ref

        driver.restore(handle, ref)  # must not raise
        assert driver.exists(handle)
