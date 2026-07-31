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
