import pytest

from phantom.storage import LocalDiskProvider, MultiRegionStore, ProviderUnavailable


def _store(tmp_path, names=("aws-us-east-1", "azure-westus", "private-cloud")):
    providers = [LocalDiskProvider(name, tmp_path / name) for name in names]
    return MultiRegionStore(providers), providers


def test_put_replicates_to_all_available_providers(tmp_path):
    store, providers = _store(tmp_path)
    written = store.put("deadbeef", b"content")
    assert written == [p.name for p in providers]
    for provider in providers:
        assert provider.has("deadbeef")


def test_put_skips_unavailable_provider_but_still_succeeds(tmp_path):
    store, providers = _store(tmp_path)
    providers[1].set_outage(True)

    written = store.put("deadbeef", b"content")

    assert providers[1].name not in written
    assert providers[0].name in written
    assert providers[2].name in written


def test_put_raises_when_every_provider_is_down(tmp_path):
    store, providers = _store(tmp_path, names=("only-region",))
    providers[0].set_outage(True)
    with pytest.raises(ProviderUnavailable):
        store.put("deadbeef", b"content")


def test_get_fails_over_to_the_next_available_provider(tmp_path):
    store, providers = _store(tmp_path)
    store.put("deadbeef", b"content")

    # Take the primary region down after the data has already landed everywhere.
    providers[0].set_outage(True)

    content, served_by = store.get("deadbeef")
    assert content == b"content"
    assert served_by != providers[0].name


def test_get_raises_when_object_unrecoverable_from_any_provider(tmp_path):
    store, providers = _store(tmp_path)
    with pytest.raises(ProviderUnavailable):
        store.get("never-written")
