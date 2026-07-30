from phantom.metrics import RPO_TARGET_SECONDS, RTO_TARGET_SECONDS
from phantom.orchestrator import PhantomInstance


def test_full_regeneration_loop(tmp_path):
    phantom = PhantomInstance(tmp_path / "phantom_state")
    phantom.init()

    phantom.write_user_file("notes.txt", "quarterly numbers")
    phantom.take_snapshot()
    phantom.write_user_file("budget.csv", "1,2,3")
    phantom.take_snapshot()

    planted = phantom.simulate_attack()
    assert "RANSOM_NOTE_README.txt" in planted

    # The regular interval snapshot fires before the operator notices and
    # manually triggers regeneration, so it captures the attacker's payload
    # too -- this is exactly why restore must go through the sanitize gate.
    phantom.take_snapshot()

    report = phantom.regenerate(reason="test: ransomware indicators")

    # Recovery mechanism meets the charter §4 targets.
    assert report.rto_seconds < RTO_TARGET_SECONDS
    assert report.rpo_seconds < RPO_TARGET_SECONDS
    assert report.rto_pass and report.rpo_pass

    # Clean data survived the regeneration; attacker payload did not.
    restored = phantom.instance.data_dir
    assert (restored / "notes.txt").read_text() == "quarterly numbers"
    assert (restored / "budget.csv").read_text() == "1,2,3"
    assert not (restored / "RANSOM_NOTE_README.txt").exists()
    assert report.files_quarantined >= 1

    # Evidence of the compromise was preserved before destruction.
    evidence_path = phantom.root / report.evidence_path
    assert (evidence_path / "data" / "RANSOM_NOTE_README.txt").exists()

    # Baseline files (security policy, motd) came back from the fresh spawn.
    assert (phantom.instance.root / "etc" / "security-policy.conf").exists()

    status = phantom.status()
    assert status["snapshot_count"] == 3
    assert any(e["event"] == "regeneration_complete" for e in status["recent_audit_events"])


def test_daily_scheduled_regeneration_is_independent_of_attack_detection(tmp_path):
    """Charter §6 Phase 2: moving-target value doesn't depend on detection
    accuracy -- a daily cadence must regenerate even with no attack at all.
    """
    phantom = PhantomInstance(tmp_path / "phantom_state")
    phantom.init()
    phantom.write_user_file("notes.txt", "hello")
    phantom.take_snapshot()

    phantom.set_policy("daily", interval_seconds=60)

    # Not due yet immediately after being set... except is_daily_due treats
    # "never regenerated" as due, matching "regenerate on schedule from day one."
    report = phantom.scheduled_check(now=1_000_000)
    assert report is not None
    assert report.reason == "scheduled: daily cadence"
    assert (phantom.instance.data_dir / "notes.txt").read_text() == "hello"

    # Immediately re-checking (same clock reading) should be a no-op.
    again = phantom.scheduled_check(now=1_000_000)
    assert again is None

    # After the interval elapses, it's due again.
    later = phantom.scheduled_check(now=1_000_061)
    assert later is not None


def test_per_session_cadence_regenerates_on_every_session_start(tmp_path):
    phantom = PhantomInstance(tmp_path / "phantom_state")
    phantom.init()
    phantom.write_user_file("notes.txt", "hello")
    phantom.take_snapshot()
    phantom.set_policy("per_session")

    first = phantom.session_start()
    assert first is not None
    assert first.reason == "scheduled: per-session cadence"

    second = phantom.session_start()
    assert second is not None  # every session start regenerates, unconditionally

    # With no cadence set, session_start should not regenerate at all.
    phantom2 = PhantomInstance(tmp_path / "phantom_state_2")
    phantom2.init()
    assert phantom2.session_start() is None


def test_regeneration_survives_a_provider_outage(tmp_path):
    """Charter §6 Phase 2 multi-region failover: losing one storage region
    must not block recovery as long as another region still has the data.
    """
    phantom = PhantomInstance(tmp_path / "phantom_state")
    phantom.init()
    phantom.write_user_file("notes.txt", "hello")
    phantom.take_snapshot()

    primary_provider = phantom.backup.providers[0].name
    phantom.backup.set_outage(primary_provider, down=True)

    report = phantom.regenerate(reason="test: provider outage")

    assert report.files_restored == 1
    assert (phantom.instance.data_dir / "notes.txt").read_text() == "hello"
