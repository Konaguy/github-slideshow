from pathlib import Path

from phantom.backup_store import BackupStore
from phantom.benchmark import (
    NOMINAL_UPLINK_MBPS,
    SNAPSHOT_INTERVAL_SECONDS,
    SnapshotSample,
    Workload,
    measure_chain_scaling,
    run_workload,
)


# -- workload generation ------------------------------------------------------

def test_materialize_creates_the_requested_shape(tmp_path):
    w = Workload("t", file_count=20, file_size_bytes=1024)
    w.materialize(tmp_path / "data")

    files = [p for p in (tmp_path / "data").rglob("*") if p.is_file()]
    assert len(files) == 20
    assert all(p.stat().st_size == 1024 for p in files)


def test_full_rewrite_churn_reports_whole_file_bytes(tmp_path):
    data = tmp_path / "data"
    w = Workload("t", file_count=10, file_size_bytes=1024, churn_fraction=0.5)
    w.materialize(data)

    changed = w.apply_churn(data, round_index=1)
    assert changed == 5 * 1024


def test_partial_edit_churn_leaves_the_rest_of_the_file_intact(tmp_path):
    """The block-level-vs-file-level case: a small edit inside a big file."""
    data = tmp_path / "data"
    w = Workload("t", file_count=4, file_size_bytes=8192, churn_fraction=0.25, edit_size_bytes=64)
    w.materialize(data)
    before = {p: p.read_bytes() for p in sorted(data.rglob("*")) if p.is_file()}

    changed = w.apply_churn(data, round_index=1)

    after = {p: p.read_bytes() for p in sorted(data.rglob("*")) if p.is_file()}
    edited = [p for p in before if before[p] != after[p]]
    assert changed == 64
    assert len(edited) == 1
    # Same length -- an in-place edit, not a rewrite.
    assert len(after[edited[0]]) == len(before[edited[0]])


def test_churn_is_deterministic_for_a_given_seed(tmp_path):
    def run(root):
        w = Workload("t", file_count=10, file_size_bytes=512, churn_fraction=0.3, seed=99)
        w.materialize(root)
        w.apply_churn(root, round_index=1)
        return sorted((str(p.relative_to(root)), p.read_bytes()) for p in root.rglob("*") if p.is_file())

    assert run(tmp_path / "a") == run(tmp_path / "b")


# -- derived metrics ----------------------------------------------------------

def test_write_amplification_and_duty_cycle_math():
    sample = SnapshotSample(
        round_index=1,
        wall_seconds=1.0,
        cpu_seconds=SNAPSHOT_INTERVAL_SECONDS * 0.10,  # 10% of the interval
        bytes_changed=1_000,
        bytes_written=10_000,
        files_scanned=5,
    )
    assert sample.write_amplification == 10.0
    assert sample.duty_cycle_pct == 10.0


def test_bandwidth_percentage_is_relative_to_the_stated_uplink():
    # Exactly 1% of the nominal uplink sustained over one interval.
    one_pct_bytes = int(NOMINAL_UPLINK_MBPS * 1_000_000 * SNAPSHOT_INTERVAL_SECONDS / 8 * 0.01)
    sample = SnapshotSample(1, 1.0, 0.0, bytes_changed=1, bytes_written=one_pct_bytes, files_scanned=1)
    assert abs(sample.bandwidth_pct - 1.0) < 0.01


def test_zero_change_does_not_divide_by_zero():
    sample = SnapshotSample(1, 0.1, 0.1, bytes_changed=0, bytes_written=0, files_scanned=0)
    assert sample.write_amplification == 0.0


def test_overhead_pass_requires_both_cpu_and_bandwidth(tmp_path):
    """§4 names CPU *and* bandwidth -- passing one is not passing."""
    result = run_workload(Workload("t", file_count=8, file_size_bytes=512), tmp_path / "r", rounds=2)

    # Force a bandwidth blowout while leaving CPU tiny.
    huge = int(NOMINAL_UPLINK_MBPS * 1_000_000 * SNAPSHOT_INTERVAL_SECONDS / 8)
    result.incremental = [SnapshotSample(1, 0.01, 0.001, bytes_changed=1, bytes_written=huge, files_scanned=1)]

    assert result.cpu_pass
    assert not result.bandwidth_pass
    assert not result.overhead_pass


# -- end to end ---------------------------------------------------------------

def test_run_workload_measures_a_full_cycle(tmp_path):
    result = run_workload(
        Workload("t", file_count=30, file_size_bytes=1024, churn_fraction=0.2),
        tmp_path / "run",
        rounds=3,
    )

    assert len(result.incremental) == 3
    assert result.files_restored == 30
    assert result.initial_snapshot.bytes_written > 0
    assert result.restore_wall_seconds > 0
    # Restoring the latest snapshot must reproduce every file.
    restored = [p for p in (tmp_path / "run" / "restored").rglob("*") if p.is_file()]
    assert len(restored) == 30


def test_partial_edits_show_higher_amplification_than_full_rewrites(tmp_path):
    """The headline finding, asserted rather than just printed: file-level
    granularity makes a small edit cost a whole-file write."""
    rewrite = run_workload(
        Workload("rewrite", file_count=8, file_size_bytes=64 * 1024, churn_fraction=0.25),
        tmp_path / "rewrite", rounds=2,
    )
    partial = run_workload(
        Workload("partial", file_count=8, file_size_bytes=64 * 1024,
                 churn_fraction=0.25, edit_size_bytes=512),
        tmp_path / "partial", rounds=2,
    )

    assert partial.mean_write_amplification > rewrite.mean_write_amplification * 10


# -- the regression this benchmark was built to catch -------------------------

def test_take_snapshot_does_not_parse_the_whole_snapshot_chain(tmp_path):
    """Snapshot cost must not scale with chain length.

    take_snapshot needs only the chain length and the parent's id, both of
    which come from manifest filenames. Parsing every manifest made
    snapshot cost climb with history -- unbounded, since the chain grows
    every 30-60s forever. Asserted structurally rather than by timing so
    it can't go flaky in CI.
    """
    data = tmp_path / "data"
    Workload("t", file_count=5, file_size_bytes=256).materialize(data)
    backup = BackupStore(tmp_path / "backups")

    for _ in range(5):
        backup.engine.take_snapshot(data)

    calls = []
    original = backup.engine._read_manifest
    backup.engine._read_manifest = lambda path: (calls.append(path), original(path))[1]

    backup.engine.take_snapshot(data)

    assert calls == [], f"take_snapshot parsed {len(calls)} manifest(s); it should parse none"


def test_snapshot_chain_stays_correct_without_the_full_parse(tmp_path):
    data = tmp_path / "data"
    Workload("t", file_count=3, file_size_bytes=256).materialize(data)
    backup = BackupStore(tmp_path / "backups")

    first = backup.engine.take_snapshot(data)
    second = backup.engine.take_snapshot(data)
    third = backup.engine.take_snapshot(data)

    assert first.parent_id is None
    assert second.parent_id == first.snapshot_id
    assert third.parent_id == second.snapshot_id
    assert len({first.snapshot_id, second.snapshot_id, third.snapshot_id}) == 3
    # latest_snapshot must agree with the fully-parsed listing.
    assert backup.engine.latest_snapshot().snapshot_id == third.snapshot_id
    assert [s.snapshot_id for s in backup.engine.list_snapshots()] == [
        first.snapshot_id, second.snapshot_id, third.snapshot_id
    ]


def test_snapshot_cost_does_not_grow_with_chain_length(tmp_path):
    timings = measure_chain_scaling(tmp_path / "probe", chain_lengths=[2, 30], file_count=60)

    short, long = timings[2], timings[30]
    # Generous bound -- this is a wall-clock check on shared CI hardware, so
    # it's here to catch an O(n) regression, not to police small variance.
    assert long < short * 4, f"snapshot cost grew {long / short:.1f}x from chain length 2 to 30"
