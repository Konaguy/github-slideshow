"""Scale benchmark for the snapshot/restore path.

Charter §9 lists "Snapshot overhead at scale" as a High-impact risk whose
mitigation is "Incremental snapshots, tiered intervals, **early
benchmarks**." Everything measured up to now has been 2-3 files on local
disk, which demonstrates the mechanism and says nothing about whether the
§4 targets survive a realistic workload. This module is the early
benchmark.

## What these numbers do and don't mean

Storage here is local disk, not S3/Azure Blob/GCS, so **absolute latency
does not transfer** -- a real deployment adds network round-trips per blob
and would be slower. What *does* transfer is everything that is a property
of the algorithm rather than the medium:

  * **write amplification** -- how many bytes reach storage per byte the
    user actually changed. This is set by snapshot granularity, and it is
    the single number that decides whether §4's "<5% bandwidth" is
    reachable. It gets *worse* on a real network, never better.
  * **CPU cost per snapshot** -- hashing and manifest handling are the same
    work regardless of where bytes land.
  * **cost growth as the snapshot chain lengthens** -- an O(n) or worse
    per-snapshot cost is a design defect that no amount of fast storage
    fixes.

Read the wall-clock figures as a floor, not a forecast.

## The §4 targets being checked

  RTO  < 5 min      recovery wall time
  RPO  < 1 min      not measured here -- it is set by snapshot interval,
                    not by engine performance
  CPU/bandwidth overhead < 5%

The overhead target needs an interval to be meaningful: "5% CPU" means 5%
of a core between snapshots. At the §5.A interval of 30-60s, a snapshot
costing 3 CPU-seconds every 30s is a 10% duty cycle and busts the budget.
`duty_cycle_pct` reports exactly that, against `SNAPSHOT_INTERVAL_SECONDS`.
"""
from __future__ import annotations

import os
import random
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from phantom.backup_store import BackupStore
from phantom.metrics import RTO_TARGET_SECONDS

# §5.A: "Block-level thin delta snapshots (30-60s intervals)". The low end
# is the conservative choice for a duty-cycle budget.
SNAPSHOT_INTERVAL_SECONDS = 30
# §4: "Snapshot CPU / bandwidth impact < 5%".
OVERHEAD_TARGET_PCT = 5.0
# The bandwidth half of that target needs a link to be a percentage *of*.
# The charter doesn't state one, so this is an explicit assumption and not
# a measurement: a per-endpoint share of a cloud uplink. Override it for a
# deployment whose real figure is known -- the point of the metric is the
# ratio it exposes, not this constant.
NOMINAL_UPLINK_MBPS = 100.0


@dataclass
class Workload:
    """A synthetic data set plus a description of how it churns."""

    name: str
    file_count: int
    file_size_bytes: int
    # Fraction of files modified between snapshots.
    churn_fraction: float = 0.05
    # Bytes rewritten within each churned file. None = rewrite the whole
    # file. A small value models the case file-level snapshots handle
    # worst: a tiny edit inside a large file.
    edit_size_bytes: Optional[int] = None
    seed: int = 1337

    @property
    def total_bytes(self) -> int:
        return self.file_count * self.file_size_bytes

    def materialize(self, data_dir: Path) -> None:
        """Write the initial data set. Content is compressible-ish text so
        the entropy heuristics elsewhere in Phantom don't flag it."""
        rng = random.Random(self.seed)
        data_dir.mkdir(parents=True, exist_ok=True)
        # Spread across subdirectories so rglob and path handling see a
        # realistic tree rather than one flat directory.
        for i in range(self.file_count):
            sub = data_dir / f"dir{i % 32:02d}"
            sub.mkdir(exist_ok=True)
            (sub / f"file{i:06d}.txt").write_bytes(_filler(rng, self.file_size_bytes))

    def apply_churn(self, data_dir: Path, round_index: int) -> int:
        """Modify a churn_fraction slice of files. Returns bytes changed."""
        rng = random.Random(self.seed + round_index)
        paths = sorted(p for p in data_dir.rglob("*") if p.is_file())
        n_churn = max(1, int(len(paths) * self.churn_fraction))
        bytes_changed = 0
        for path in rng.sample(paths, min(n_churn, len(paths))):
            if self.edit_size_bytes is None:
                path.write_bytes(_filler(rng, self.file_size_bytes))
                bytes_changed += self.file_size_bytes
            else:
                # In-place edit of a slice, leaving the rest of the file
                # byte-identical -- the block-level-vs-file-level case.
                data = bytearray(path.read_bytes())
                edit = min(self.edit_size_bytes, len(data))
                offset = rng.randrange(0, max(1, len(data) - edit))
                data[offset:offset + edit] = _filler(rng, edit)
                path.write_bytes(bytes(data))
                bytes_changed += edit
        return bytes_changed


def _filler(rng: random.Random, size: int) -> bytes:
    """Low-entropy filler: repeated words, like documents and logs."""
    words = [b"alpha ", b"bravo ", b"charlie ", b"delta ", b"echo "]
    out = bytearray()
    while len(out) < size:
        out += rng.choice(words)
    return bytes(out[:size])


@dataclass
class SnapshotSample:
    round_index: int
    wall_seconds: float
    cpu_seconds: float
    bytes_changed: int
    bytes_written: int
    files_scanned: int

    @property
    def write_amplification(self) -> float:
        if self.bytes_changed == 0:
            return 0.0
        return self.bytes_written / self.bytes_changed

    @property
    def duty_cycle_pct(self) -> float:
        """CPU-seconds per snapshot as a % of the snapshot interval."""
        return 100.0 * self.cpu_seconds / SNAPSHOT_INTERVAL_SECONDS

    @property
    def required_mbps(self) -> float:
        """Sustained uplink needed to ship this snapshot within one interval."""
        return (self.bytes_written * 8) / (SNAPSHOT_INTERVAL_SECONDS * 1_000_000)

    @property
    def bandwidth_pct(self) -> float:
        """Required throughput as a % of NOMINAL_UPLINK_MBPS."""
        return 100.0 * self.required_mbps / NOMINAL_UPLINK_MBPS


@dataclass
class BenchmarkResult:
    workload: Workload
    initial_snapshot: SnapshotSample
    incremental: list = field(default_factory=list)
    restore_wall_seconds: float = 0.0
    restore_cpu_seconds: float = 0.0
    stored_bytes: int = 0
    files_restored: int = 0

    @property
    def mean_incremental_wall(self) -> float:
        return _mean([s.wall_seconds for s in self.incremental])

    @property
    def mean_write_amplification(self) -> float:
        return _mean([s.write_amplification for s in self.incremental])

    @property
    def mean_duty_cycle_pct(self) -> float:
        return _mean([s.duty_cycle_pct for s in self.incremental])

    @property
    def mean_bandwidth_pct(self) -> float:
        return _mean([s.bandwidth_pct for s in self.incremental])

    @property
    def mean_required_mbps(self) -> float:
        return _mean([s.required_mbps for s in self.incremental])

    @property
    def snapshot_cost_growth(self) -> float:
        """Last incremental snapshot's wall time / first incremental's.

        Snapshots do identical work each round -- same file count, same
        churn -- so this should sit near 1.0. Anything that climbs with
        chain length is per-snapshot cost scaling with history, which is a
        design defect rather than a storage-speed problem.
        """
        if len(self.incremental) < 2:
            return 1.0
        first = self.incremental[0].wall_seconds
        if first <= 0:
            return 1.0
        return self.incremental[-1].wall_seconds / first

    @property
    def rto_pass(self) -> bool:
        return self.restore_wall_seconds < RTO_TARGET_SECONDS

    @property
    def cpu_pass(self) -> bool:
        return self.mean_duty_cycle_pct < OVERHEAD_TARGET_PCT

    @property
    def bandwidth_pass(self) -> bool:
        return self.mean_bandwidth_pct < OVERHEAD_TARGET_PCT

    @property
    def overhead_pass(self) -> bool:
        """§4 names CPU *and* bandwidth; both have to clear the budget."""
        return self.cpu_pass and self.bandwidth_pass

    def summary(self) -> str:
        w = self.workload
        lines = [
            f"Workload: {w.name}",
            f"  {w.file_count:,} files x {_human(w.file_size_bytes)} = {_human(w.total_bytes)}"
            f"   churn {w.churn_fraction:.0%}"
            + (f", {_human(w.edit_size_bytes)} edit per file" if w.edit_size_bytes else ", full-file rewrite"),
            "",
            f"  initial snapshot   {self.initial_snapshot.wall_seconds:8.2f}s wall"
            f"  {self.initial_snapshot.cpu_seconds:7.2f}s cpu"
            f"  {_human(self.initial_snapshot.bytes_written)} written",
            f"  incremental (mean) {self.mean_incremental_wall:8.2f}s wall"
            f"  {_mean([s.cpu_seconds for s in self.incremental]):7.2f}s cpu"
            f"  {_human(int(_mean([s.bytes_written for s in self.incremental])))} written",
            f"  restore (RTO)      {self.restore_wall_seconds:8.2f}s wall"
            f"  {self.restore_cpu_seconds:7.2f}s cpu"
            f"  {self.files_restored:,} files",
            "",
            f"  write amplification  {self.mean_write_amplification:8.1f}x"
            f"   (bytes to storage per byte changed)",
            f"  cpu duty cycle       {self.mean_duty_cycle_pct:8.1f}%"
            f"   (target < {OVERHEAD_TARGET_PCT}% at {SNAPSHOT_INTERVAL_SECONDS}s interval)"
            f"   {'PASS' if self.cpu_pass else 'FAIL'}",
            f"  bandwidth            {self.mean_bandwidth_pct:8.1f}%"
            f"   ({self.mean_required_mbps:.1f} Mbps sustained vs {NOMINAL_UPLINK_MBPS:.0f} Mbps assumed)"
            f"   {'PASS' if self.bandwidth_pass else 'FAIL'}",
            f"  snapshot cost growth {self.snapshot_cost_growth:8.2f}x"
            f"   (last incremental / first; ~1.0 is flat)",
            f"  RTO                  {self.restore_wall_seconds:8.2f}s"
            f"   (target < {RTO_TARGET_SECONDS}s)"
            f"   {'PASS' if self.rto_pass else 'FAIL'}",
            f"  stored on disk       {_human(self.stored_bytes)}"
            f"   across all providers",
        ]
        return "\n".join(lines)


def run_workload(workload: Workload, root: Path, rounds: int = 5) -> BenchmarkResult:
    """Materialize the workload, snapshot it, churn+snapshot `rounds` times,
    then restore the latest snapshot and measure it."""
    root.mkdir(parents=True, exist_ok=True)
    data_dir = root / "data"
    backup = BackupStore(root / "backups")

    workload.materialize(data_dir)

    initial = _timed_snapshot(backup, data_dir, round_index=0, bytes_changed=workload.total_bytes)
    result = BenchmarkResult(workload=workload, initial_snapshot=initial)

    for i in range(1, rounds + 1):
        changed = workload.apply_churn(data_dir, round_index=i)
        result.incremental.append(_timed_snapshot(backup, data_dir, round_index=i, bytes_changed=changed))

    latest = backup.engine.latest_snapshot()
    restore_dir = root / "restored"
    wall_start, cpu_start = time.perf_counter(), time.process_time()
    backup.engine.restore(latest, restore_dir)
    result.restore_wall_seconds = time.perf_counter() - wall_start
    result.restore_cpu_seconds = time.process_time() - cpu_start
    result.files_restored = len(latest.files)
    result.stored_bytes = _dir_size(root / "backups")

    return result


def _timed_snapshot(backup: BackupStore, data_dir: Path, round_index: int, bytes_changed: int) -> SnapshotSample:
    before = _dir_size(backup.root / "providers")
    wall_start, cpu_start = time.perf_counter(), time.process_time()
    snap = backup.engine.take_snapshot(data_dir)
    wall = time.perf_counter() - wall_start
    cpu = time.process_time() - cpu_start
    after = _dir_size(backup.root / "providers")
    return SnapshotSample(
        round_index=round_index,
        wall_seconds=wall,
        cpu_seconds=cpu,
        bytes_changed=bytes_changed,
        bytes_written=max(0, after - before),
        files_scanned=len(snap.files),
    )


# -- Scale presets ------------------------------------------------------------
#
# `smoke` exists so the test suite can exercise this path in CI in well
# under a second. The larger presets are opt-in from the CLI.

SCALES = {
    "smoke": [
        Workload("smoke", file_count=40, file_size_bytes=2 * 1024, churn_fraction=0.10),
    ],
    "small": [
        Workload("small-many-small-files", file_count=2_000, file_size_bytes=4 * 1024, churn_fraction=0.05),
        Workload("small-few-large-files", file_count=20, file_size_bytes=2 * 1024 * 1024,
                 churn_fraction=0.20, edit_size_bytes=4 * 1024),
    ],
    "medium": [
        Workload("medium-many-small-files", file_count=20_000, file_size_bytes=8 * 1024, churn_fraction=0.05),
        Workload("medium-few-large-files", file_count=100, file_size_bytes=16 * 1024 * 1024,
                 churn_fraction=0.10, edit_size_bytes=4 * 1024),
    ],
    "large": [
        Workload("large-many-small-files", file_count=100_000, file_size_bytes=8 * 1024, churn_fraction=0.02),
        Workload("large-few-large-files", file_count=200, file_size_bytes=64 * 1024 * 1024,
                 churn_fraction=0.05, edit_size_bytes=4 * 1024),
    ],
}


def measure_chain_scaling(root: Path, chain_lengths: list, file_count: int = 500) -> dict:
    """Cost of one snapshot at increasing chain lengths.

    This is separate from `run_workload` because it varies chain length
    rather than data size, and it is the probe that matters most: anything
    here that grows with chain length is unbounded in production, where
    the chain grows by one every 30-60s forever. A fixed workload is
    re-snapshotted, so any growth is per-snapshot overhead scaling with
    history rather than more user data.

    Returns {chain_length: seconds_for_one_snapshot}.
    """
    root.mkdir(parents=True, exist_ok=True)
    data_dir = root / "data"
    Workload("chain-probe", file_count=file_count, file_size_bytes=512).materialize(data_dir)
    backup = BackupStore(root / "backups")

    timings = {}
    target = max(chain_lengths)
    for i in range(1, target + 1):
        backup.engine.take_snapshot(data_dir)
        if i in chain_lengths:
            start = time.perf_counter()
            backup.engine.take_snapshot(data_dir)
            timings[i] = time.perf_counter() - start
    return timings


def run_scale(scale: str, root: Path, rounds: int = 5, keep: bool = False) -> list:
    """Run every workload in a named scale preset."""
    if scale not in SCALES:
        raise KeyError(f"unknown scale {scale!r}; choose from {sorted(SCALES)}")
    results = []
    for workload in SCALES[scale]:
        workload_root = root / workload.name
        if workload_root.exists():
            shutil.rmtree(workload_root)
        try:
            results.append(run_workload(workload, workload_root, rounds=rounds))
        finally:
            if not keep and workload_root.exists():
                shutil.rmtree(workload_root)
    return results


# -- helpers ------------------------------------------------------------------

def _dir_size(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for name in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
    return total


def _mean(values: list) -> float:
    return sum(values) / len(values) if values else 0.0


def _human(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(size) < 1024.0 or unit == "GiB":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}GiB"
