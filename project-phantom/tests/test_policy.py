from phantom.policy import RegenerationPolicy


def test_daily_due_immediately_after_being_set(tmp_path):
    policy = RegenerationPolicy(tmp_path / "policy.json")
    policy.set("daily", interval_seconds=60)
    assert policy.is_daily_due(now=1_000_000) is True


def test_daily_not_due_until_interval_elapses(tmp_path):
    policy = RegenerationPolicy(tmp_path / "policy.json")
    policy.set("daily", interval_seconds=60)
    policy.mark_regenerated(at=1_000_000)

    assert policy.is_daily_due(now=1_000_030) is False
    assert policy.is_daily_due(now=1_000_061) is True


def test_per_session_cadence_is_never_daily_due(tmp_path):
    policy = RegenerationPolicy(tmp_path / "policy.json")
    policy.set("per_session")
    assert policy.is_daily_due(now=1_000_000) is False


def test_no_policy_set_is_never_due(tmp_path):
    policy = RegenerationPolicy(tmp_path / "policy.json")
    assert policy.is_daily_due() is False
    assert policy.load() is None


def test_set_preserves_last_regenerated_at_across_updates(tmp_path):
    policy = RegenerationPolicy(tmp_path / "policy.json")
    policy.set("daily", interval_seconds=60)
    policy.mark_regenerated(at=500)

    policy.set("daily", interval_seconds=120)
    assert policy.load().last_regenerated_at == 500
