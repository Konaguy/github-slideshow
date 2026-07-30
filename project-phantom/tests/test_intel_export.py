import json

from phantom.fleet import ThreatIntelFeed
from phantom.intel_export import (
    DEFAULT_TTL_SECONDS,
    IntelExporter,
    RevocationList,
    verify_bundle,
)

DAY = 24 * 60 * 60


def _exporter(tmp_path, ttl_seconds=DEFAULT_TTL_SECONDS):
    feed = ThreatIntelFeed(tmp_path / "feed.jsonl")
    revocations = RevocationList(tmp_path / "revocations.json")
    return feed, revocations, IntelExporter(feed, revocations, ttl_seconds=ttl_seconds)


def test_export_includes_live_indicators(tmp_path):
    feed, _revocations, exporter = _exporter(tmp_path)
    feed.publish({"aaa", "bbb"}, label="ransomware.x", source_fingerprint="src1")

    bundle = exporter.export()

    assert bundle.indicator_count == 2
    assert bundle.tier == "intel"
    assert {i["content_hash"] for i in bundle.indicators} == {"aaa", "bbb"}


def test_revoked_indicators_are_excluded(tmp_path):
    feed, revocations, exporter = _exporter(tmp_path)
    feed.publish({"aaa", "bbb"}, label="ransomware.x", source_fingerprint="src1")
    revocations.revoke("aaa")

    bundle = exporter.export()

    assert bundle.indicator_count == 1
    assert {i["content_hash"] for i in bundle.indicators} == {"bbb"}


def test_unrevoking_restores_an_indicator(tmp_path):
    feed, revocations, exporter = _exporter(tmp_path)
    feed.publish({"aaa"}, label="ransomware.x", source_fingerprint="src1")
    revocations.revoke("aaa")
    assert exporter.export().indicator_count == 0

    revocations.unrevoke("aaa")

    assert exporter.export().indicator_count == 1


def test_expired_indicators_are_filtered_out(tmp_path):
    feed, _revocations, exporter = _exporter(tmp_path, ttl_seconds=DAY)
    feed.publish({"aaa"}, label="ransomware.x", source_fingerprint="src1")

    import time as _time
    still_live = exporter.export(now=_time.time() + DAY / 2)
    expired = exporter.export(now=_time.time() + DAY * 2)

    assert still_live.indicator_count == 1
    assert expired.indicator_count == 0


def test_community_tier_gets_a_narrower_window(tmp_path):
    import time as _time

    feed, _revocations, exporter = _exporter(tmp_path)
    feed.publish({"aaa"}, label="ransomware.x", source_fingerprint="src1")

    # 30 days later the indicator is outside community's 7-day window but
    # still inside the intel tier's full history.
    later = _time.time() + 30 * DAY
    assert exporter.export(tier="community", now=later).indicator_count == 0
    assert exporter.export(tier="intel", now=later).indicator_count == 1


def test_unknown_tier_is_rejected(tmp_path):
    import pytest

    _feed, _revocations, exporter = _exporter(tmp_path)
    with pytest.raises(ValueError):
        exporter.export(tier="enterprise-platinum")


def test_bundle_verifies_against_its_own_digest(tmp_path):
    feed, _revocations, exporter = _exporter(tmp_path)
    feed.publish({"aaa", "bbb"}, label="ransomware.x", source_fingerprint="src1")

    bundle = exporter.export()

    assert verify_bundle(bundle.to_json()) == []


def test_modified_bundle_fails_verification(tmp_path):
    feed, _revocations, exporter = _exporter(tmp_path)
    feed.publish({"aaa"}, label="ransomware.x", source_fingerprint="src1")
    data = json.loads(exporter.export().to_json())

    # Someone slips an extra indicator into the bundle in transit.
    data["indicators"].append({
        "content_hash": "evil", "label": "spoofed",
        "published_at": "2026-01-01T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z",
    })

    problems = verify_bundle(json.dumps(data))

    assert any("integrity_digest" in p or "indicator_count" in p for p in problems)


def test_malformed_bundle_is_reported_not_raised(tmp_path):
    problems = verify_bundle("{not json")
    assert problems and "valid JSON" in problems[0]


def test_export_to_file_writes_readable_bundle(tmp_path):
    feed, _revocations, exporter = _exporter(tmp_path)
    feed.publish({"aaa"}, label="ransomware.x", source_fingerprint="src1")

    out = tmp_path / "bundles" / "feed.json"
    bundle = exporter.export_to_file(out, tier="intel")

    assert out.exists()
    assert verify_bundle(out.read_text()) == []
    assert bundle.indicator_count == 1
