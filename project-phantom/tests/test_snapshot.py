from phantom.snapshot import SnapshotEngine
from phantom.storage import LocalDiskProvider, MultiRegionStore


def _engine(tmp_path, provider_names=("region-a", "region-b")):
    providers = [LocalDiskProvider(name, tmp_path / "providers" / name) for name in provider_names]
    store = MultiRegionStore(providers)
    return SnapshotEngine(tmp_path / "control", store), providers


def test_snapshot_dedups_unchanged_content(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "a.txt").write_text("hello")

    engine, providers = _engine(tmp_path)

    first = engine.take_snapshot(data_dir)
    objects_after_first = list(providers[0].objects_dir.iterdir())
    assert len(objects_after_first) == 1

    # Unchanged file -> second snapshot should not add a new blob.
    second = engine.take_snapshot(data_dir)
    assert list(providers[0].objects_dir.iterdir()) == objects_after_first
    assert second.files["a.txt"] == first.files["a.txt"]
    assert second.parent_id == first.snapshot_id

    # Changed file -> exactly one new blob.
    (data_dir / "a.txt").write_text("world")
    third = engine.take_snapshot(data_dir)
    assert len(list(providers[0].objects_dir.iterdir())) == 2
    assert third.files["a.txt"] != first.files["a.txt"]


def test_take_snapshot_replicates_to_every_provider(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "a.txt").write_text("hello")

    engine, providers = _engine(tmp_path, provider_names=("region-a", "region-b", "region-c"))
    engine.take_snapshot(data_dir)

    for provider in providers:
        assert len(list(provider.objects_dir.iterdir())) == 1


def test_restore_reconstructs_files(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "a.txt").write_text("hello")
    (data_dir / "nested").mkdir()
    (data_dir / "nested" / "b.txt").write_text("world")

    engine, _providers = _engine(tmp_path)
    snap = engine.take_snapshot(data_dir)

    dest = tmp_path / "restored"
    engine.restore(snap, dest)

    assert (dest / "a.txt").read_text() == "hello"
    assert (dest / "nested" / "b.txt").read_text() == "world"
