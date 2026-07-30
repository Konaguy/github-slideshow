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

    # Evidence of the compromise was preserved into the forensic vault
    # before destruction, and the chain of custody verifies.
    evidence_path = phantom.root / report.evidence_path
    assert (evidence_path / "artifacts" / "RANSOM_NOTE_README.txt").exists()
    assert phantom.vault.verify_chain() == []

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


def test_detection_auto_triggers_regeneration_and_recovers_clean_data(tmp_path):
    """Charter §5.D: anomalous deltas trigger regeneration, with no
    manual trigger and no pre-seeded known-bad hashes.
    """
    phantom = PhantomInstance(tmp_path / "phantom_state")
    phantom.init()
    phantom.write_user_file("notes.txt", "the quarterly numbers are good " * 10)
    phantom.write_user_file("budget.csv", "revenue,cost\n100,50\n" * 20)
    clean_snapshot = phantom.take_snapshot()

    # Ransomware encrypts everything in place; the next interval snapshot
    # captures the damage before anyone has noticed.
    phantom.simulate_encryption_attack()
    phantom.take_snapshot()

    result, report = phantom.detect_and_respond()

    assert result.is_anomalous, result.summary()
    assert report is not None, "anomalous delta should have triggered regeneration"

    # Recovery came from the pre-attack snapshot, so the plaintext is back.
    assert "quarterly numbers" in (phantom.instance.data_dir / "notes.txt").read_text()
    assert "revenue,cost" in (phantom.instance.data_dir / "budget.csv").read_text()
    assert clean_snapshot.snapshot_id in report.reason or report.files_restored == 2

    # The compromised state was preserved in the vault first, chain intact.
    assert phantom.vault.verify_chain() == []
    assert len(phantom.vault.entries()) == 1


def test_benign_activity_does_not_trigger_regeneration(tmp_path):
    """The false-positive side: ordinary edits must not cause a rebuild."""
    phantom = PhantomInstance(tmp_path / "phantom_state")
    phantom.init()
    for name in ("a.txt", "b.txt", "c.txt", "d.txt"):
        phantom.write_user_file(name, f"ordinary plain text content for {name} " * 10)
    phantom.take_snapshot()

    phantom.write_user_file("a.txt", "ordinary plain text content for a.txt " * 10 + "with an edit")
    phantom.take_snapshot()

    result, report = phantom.detect_and_respond()

    assert not result.is_anomalous, result.summary()
    assert report is None
    assert phantom.vault.entries() == []  # nothing destroyed, nothing to preserve


def test_fleet_immunity_hardens_an_uncompromised_instance(tmp_path):
    """Charter §5.H: one instance's attack becomes another's immunity."""
    feed_path = tmp_path / "fleet_feed.jsonl"

    attacked = PhantomInstance(tmp_path / "vm_a", feed_path=feed_path, instance_id="phantom-vm-a")
    attacked.init()
    attacked.write_user_file("notes.txt", "hello")
    attacked.take_snapshot()

    bystander = PhantomInstance(tmp_path / "vm_b", feed_path=feed_path, instance_id="phantom-vm-b")
    bystander.init()
    bystander.write_user_file("notes.txt", "hello")
    bystander.take_snapshot()
    assert bystander.blocklist.load() == set(), "bystander starts with no indicators"

    # VM A is hit and responds; its indicators go to the shared feed.
    attacked.simulate_attack()
    attacked.take_snapshot()
    result, report = attacked.detect_and_respond()
    assert result.is_anomalous
    assert report is not None
    assert feed_path.exists(), "responding instance should publish indicators"

    # VM B, never attacked, pulls the feed and hardens pre-emptively.
    learned = bystander.pull_fleet_intel()
    assert learned > 0
    assert bystander.blocklist.load() >= attacked.feed.hashes()

    # Now the same payload arriving at VM B is quarantined on restore.
    bystander.simulate_attack()
    bystander.take_snapshot()
    bystander_report = bystander.regenerate(reason="test: post-immunity restore")
    assert bystander_report.files_quarantined >= 1
    assert not (bystander.instance.data_dir / "invoice.pdf.exe").exists()


def test_intel_opt_out_publishes_nothing_but_still_regenerates(tmp_path):
    """Charter §9 mitigation: sharing is opt-in; protection is not."""
    feed_path = tmp_path / "fleet_feed.jsonl"
    phantom = PhantomInstance(tmp_path / "vm", feed_path=feed_path, instance_id="phantom-vm-optout")
    phantom.init()
    phantom.write_user_file("notes.txt", "hello")
    phantom.take_snapshot()

    phantom.simulate_attack()
    phantom.take_snapshot()
    result, report = phantom.detect_and_respond(share_intel=False)

    assert result.is_anomalous
    assert report is not None, "opting out of sharing must not disable protection"
    assert phantom.feed.hashes() == set(), "nothing should have been published"


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
