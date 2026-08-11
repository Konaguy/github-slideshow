import hashlib
import os

from phantom.detection import DetectionEngine
from phantom.snapshot import Snapshot


class FakeBlobStore:
    """Stands in for the snapshot engine's content-addressed store."""

    def __init__(self):
        self.blobs = {}

    def add(self, content: bytes) -> str:
        digest = hashlib.sha256(content).hexdigest()
        self.blobs[digest] = content
        return digest

    def read(self, digest: str) -> bytes:
        return self.blobs[digest]


def _snapshot(snapshot_id, files, parent_id=None, kind="interval"):
    return Snapshot(
        snapshot_id=snapshot_id, taken_at="2026-07-30T12:00:00Z",
        parent_id=parent_id, files=files, kind=kind,
    )


def test_first_snapshot_is_never_anomalous():
    store = FakeBlobStore()
    engine = DetectionEngine(read_blob=store.read)
    current = _snapshot("s1", {"a.txt": store.add(b"hello")})

    result = engine.evaluate(None, current)

    assert result.score == 0.0
    assert not result.is_anomalous


def test_ordinary_edit_is_not_anomalous():
    store = FakeBlobStore()
    engine = DetectionEngine(read_blob=store.read)
    text = ("the quick brown fox jumps over the lazy dog " * 10).encode()
    previous = _snapshot("s1", {
        "a.txt": store.add(text),
        "b.txt": store.add(text + b" second file"),
        "c.txt": store.add(text + b" third file"),
        "d.txt": store.add(text + b" fourth file"),
    })
    # One file edited, still plain text -- the everyday case.
    current = _snapshot("s2", {
        "a.txt": store.add(text + b" edited"),
        "b.txt": previous.files["b.txt"],
        "c.txt": previous.files["c.txt"],
        "d.txt": previous.files["d.txt"],
    })

    result = engine.evaluate(previous, current)

    assert not result.is_anomalous, result.summary()


def test_mass_rewrite_with_entropy_spike_is_anomalous():
    """The in-place-encryption shape: most files rewritten, text -> random."""
    store = FakeBlobStore()
    engine = DetectionEngine(read_blob=store.read)
    text = ("the quick brown fox jumps over the lazy dog " * 10).encode()
    names = [f"f{i}.txt" for i in range(8)]
    previous = _snapshot("s1", {n: store.add(text + n.encode()) for n in names})
    current = _snapshot("s2", {n: store.add(os.urandom(2048)) for n in names})

    result = engine.evaluate(previous, current)

    assert result.is_anomalous
    fired = {s.name for s in result.signals}
    assert "mass_rewrite" in fired
    assert "entropy_spike" in fired


def test_bulk_rewrite_without_entropy_change_stays_below_threshold():
    """A formatter or find-and-replace touches every file but doesn't
    encrypt anything -- not worth destroying someone's desktop over.
    """
    store = FakeBlobStore()
    engine = DetectionEngine(read_blob=store.read)
    names = [f"f{i}.txt" for i in range(8)]
    previous = _snapshot("s1", {n: store.add(("plain text " * 20 + n).encode()) for n in names})
    current = _snapshot("s2", {n: store.add(("plain text reformatted " * 20 + n).encode()) for n in names})

    result = engine.evaluate(previous, current)

    assert "mass_rewrite" in {s.name for s in result.signals}
    assert not result.is_anomalous, result.summary()


def test_mass_change_signals_are_suppressed_on_tiny_file_counts():
    """Editing one of your two documents is not a mass rewrite."""
    store = FakeBlobStore()
    engine = DetectionEngine(read_blob=store.read)
    previous = _snapshot("s1", {
        "notes.txt": store.add(b"plain text content here"),
        "budget.csv": store.add(b"revenue,cost\n100,50\n"),
    })
    current = _snapshot("s2", {
        "notes.txt": store.add(b"plain text content here, edited"),
        "budget.csv": previous.files["budget.csv"],
    })

    result = engine.evaluate(previous, current)

    assert result.signals == [], result.summary()
    assert not result.is_anomalous


def test_mass_deletion_is_anomalous():
    store = FakeBlobStore()
    engine = DetectionEngine(read_blob=store.read)
    previous = _snapshot("s1", {f"f{i}.txt": store.add(f"content {i}".encode()) for i in range(8)})
    current = _snapshot("s2", {"f0.txt": previous.files["f0.txt"]})

    result = engine.evaluate(previous, current)

    assert result.is_anomalous
    assert "mass_deletion" in {s.name for s in result.signals}


def test_suspicious_arrival_is_anomalous():
    """A dropped ransom note alone should clear the threshold."""
    store = FakeBlobStore()
    engine = DetectionEngine(read_blob=store.read)
    previous = _snapshot("s1", {"a.txt": store.add(b"hello")})
    current = _snapshot("s2", {
        "a.txt": previous.files["a.txt"],
        "RANSOM_NOTE_README.txt": store.add(b"pay up"),
    })

    result = engine.evaluate(previous, current)

    assert result.is_anomalous
    assert "suspicious_arrivals" in {s.name for s in result.signals}


def test_score_is_capped_at_one():
    store = FakeBlobStore()
    engine = DetectionEngine(read_blob=store.read)
    text = ("plain text content that is definitely not random " * 10).encode()
    names = [f"f{i}.txt" for i in range(8)]
    previous = _snapshot("s1", {n: store.add(text + n.encode()) for n in names})
    # Everything rewritten to high entropy AND a ransom note dropped.
    current = _snapshot("s2", {
        **{n: store.add(os.urandom(2048)) for n in names},
        "RANSOM_NOTE_README.txt": store.add(b"pay up"),
    })

    result = engine.evaluate(previous, current)

    assert result.score == 1.0
    assert result.is_anomalous


def test_post_regeneration_snapshot_is_never_scored_as_drift():
    """Phantom's own rebuild changes every file at once. Scoring that as an
    anomaly makes the response to an attack look like another attack --
    a rebuild loop.
    """
    store = FakeBlobStore()
    engine = DetectionEngine(read_blob=store.read)
    names = [f"f{i}.txt" for i in range(8)]
    # Prior snapshot is the compromised state: everything encrypted.
    previous = _snapshot("s1", {n: store.add(os.urandom(2048)) for n in names})
    # Recovery restores clean plaintext -- a 100% rewrite, by design.
    recovered = _snapshot(
        "s2",
        {n: store.add(("recovered plain text " * 20 + n).encode()) for n in names},
        kind="post_regeneration",
    )

    result = engine.evaluate(previous, recovered)

    assert result.score == 0.0
    assert result.signals == []
    assert not result.is_anomalous


def test_interval_snapshot_after_recovery_is_scored_normally():
    """Suppression applies only to the recovery snapshot itself, not to
    everything that follows it -- an attack right after a rebuild must
    still be caught.
    """
    store = FakeBlobStore()
    engine = DetectionEngine(read_blob=store.read)
    names = [f"f{i}.txt" for i in range(8)]
    recovered = _snapshot(
        "s2",
        {n: store.add(("recovered plain text " * 20 + n).encode()) for n in names},
        kind="post_regeneration",
    )
    reattacked = _snapshot("s3", {n: store.add(os.urandom(2048)) for n in names})

    result = engine.evaluate(recovered, reattacked)

    assert result.is_anomalous, result.summary()


def test_unreadable_blob_does_not_crash_or_false_fire():
    """A storage outage is a storage problem, not an attack signal."""
    store = FakeBlobStore()
    engine = DetectionEngine(read_blob=store.read)
    previous = _snapshot("s1", {"a.txt": store.add(b"hello world padding")})
    # Reference a digest that was never stored -- simulates a provider outage.
    current = _snapshot("s2", {"a.txt": "0" * 64})

    result = engine.evaluate(previous, current)

    assert result.score == 0.0
    assert not result.is_anomalous
