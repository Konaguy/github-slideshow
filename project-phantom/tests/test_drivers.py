"""Local driver tests + the shared conformance suite.

EC2 lives in test_drivers_aws.py because that module skips wholesale when
boto3/moto are absent -- keeping them separate means a bare environment
still runs the contract against the local driver instead of silently
skipping every driver test.
"""
import pytest

from phantom.drivers import (
    PHANTOM_INSTANCE_TAG,
    PHANTOM_MANAGED_TAG,
    PHANTOM_MANAGED_VALUE,
    ComputeDriver,
    ComputeDriverConformance,
    DestroyRefused,
    InstanceHandle,
    LocalDriver,
)

# -- Local driver -------------------------------------------------------------

class TestLocalDriverConformance(ComputeDriverConformance):
    """The local driver held to the shared contract."""

    @pytest.fixture(autouse=True)
    def _tmp(self, tmp_path):
        self._root = tmp_path

    def make_driver(self):
        return LocalDriver(self._root / "instances")

    def make_baseline(self, driver) -> str:
        baseline = self._root / "baseline"
        baseline.mkdir(exist_ok=True)
        (baseline / "motd").write_text("hardened baseline\n")
        return str(baseline)

    def make_foreign_handle(self, driver) -> InstanceHandle:
        """A directory that looks like an instance but carries no marker --
        i.e. something Phantom did not create and must not delete."""
        foreign = driver.root / "not-ours"
        (foreign / "data").mkdir(parents=True, exist_ok=True)
        (foreign / "data" / "important.txt").write_text("someone else's production data")
        return InstanceHandle(provider=driver.provider, native_id="not-ours", instance_id="not-ours")


def test_local_driver_satisfies_the_protocol(tmp_path):
    assert isinstance(LocalDriver(tmp_path), ComputeDriver)


def test_local_spawn_writes_the_managed_marker(tmp_path):
    driver = LocalDriver(tmp_path / "instances")
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    (baseline / "motd").write_text("x")

    handle = driver.spawn(str(baseline), "vm-1")

    import json
    marker = json.loads((driver.root / handle.native_id / ".phantom-instance.json").read_text())
    assert marker[PHANTOM_MANAGED_TAG] == PHANTOM_MANAGED_VALUE
    assert marker[PHANTOM_INSTANCE_TAG] == "vm-1"


def test_local_destroy_leaves_foreign_data_untouched(tmp_path):
    """The failure this guard exists to prevent: deleting data we didn't create."""
    driver = LocalDriver(tmp_path / "instances")
    foreign = driver.root / "prod-db"
    (foreign / "data").mkdir(parents=True)
    payload = foreign / "data" / "customers.csv"
    payload.write_text("real data")

    handle = InstanceHandle(provider=driver.provider, native_id="prod-db", instance_id="prod-db")
    with pytest.raises(DestroyRefused):
        driver.destroy(handle)

    assert payload.read_text() == "real data"


def test_local_corrupt_marker_is_treated_as_not_managed(tmp_path):
    """A marker we can't parse must fail closed, not open."""
    driver = LocalDriver(tmp_path / "instances")
    target = driver.root / "corrupt"
    target.mkdir(parents=True)
    (target / ".phantom-instance.json").write_text("{not json")

    handle = InstanceHandle(provider=driver.provider, native_id="corrupt", instance_id="corrupt")
    with pytest.raises(DestroyRefused):
        driver.destroy(handle)


def test_local_snapshot_restore_round_trips_content(tmp_path):
    driver = LocalDriver(tmp_path / "instances")
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    (baseline / "notes.txt").write_text("original")

    handle = driver.spawn(str(baseline), "vm-1")
    ref = driver.snapshot(handle)

    (driver.data_path(handle) / "notes.txt").write_text("mutated")
    driver.restore(handle, ref)

    assert (driver.data_path(handle) / "notes.txt").read_text() == "original"
