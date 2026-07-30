from phantom.fleet import ThreatIntelFeed


def test_publish_and_read_indicators(tmp_path):
    feed = ThreatIntelFeed(tmp_path / "feed.jsonl")
    published = feed.publish({"aaa", "bbb"}, label="ransomware.x", source_fingerprint="abc123")

    assert len(published) == 2
    assert feed.hashes() == {"aaa", "bbb"}


def test_publish_is_idempotent_for_known_indicators(tmp_path):
    feed = ThreatIntelFeed(tmp_path / "feed.jsonl")
    feed.publish({"aaa"}, label="ransomware.x", source_fingerprint="abc123")
    republished = feed.publish({"aaa", "bbb"}, label="ransomware.x", source_fingerprint="abc123")

    assert [i.content_hash for i in republished] == ["bbb"]
    assert feed.hashes() == {"aaa", "bbb"}


def test_opt_out_publishes_nothing(tmp_path):
    """Charter §9: threat-intel sharing is customer opt-in."""
    feed = ThreatIntelFeed(tmp_path / "feed.jsonl")
    published = feed.publish({"aaa"}, label="ransomware.x", source_fingerprint="abc123", share=False)

    assert published == []
    assert feed.hashes() == set()


def test_indicators_carry_no_content_or_paths(tmp_path):
    """Anonymization: hash + coarse label only, never file bytes or names."""
    feed = ThreatIntelFeed(tmp_path / "feed.jsonl")
    feed.publish({"aaa"}, label="ransomware.x", source_fingerprint="abc123")

    raw = feed.path.read_text()
    indicator = feed.indicators()[0]

    assert set(indicator.__dict__) == {"content_hash", "label", "published_at", "source_fingerprint"}
    assert "/" not in raw.replace("\\/", "")  # no file paths leaked into the feed


def test_empty_feed_reads_as_empty(tmp_path):
    feed = ThreatIntelFeed(tmp_path / "never-written.jsonl")
    assert feed.indicators() == []
    assert feed.hashes() == set()
