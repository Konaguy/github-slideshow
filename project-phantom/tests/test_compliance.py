from phantom.compliance import DISCLAIMER, ComplianceReporter
from phantom.orchestrator import PhantomInstance


def test_report_on_a_fresh_instance_finds_missing_evidence(tmp_path):
    phantom = PhantomInstance(tmp_path / "state")
    phantom.init()

    report = phantom.compliance.generate()

    # Nothing has happened yet, so detection/recovery controls have no evidence.
    unsatisfied = {c.control_id for c in report.controls if not c.satisfied}
    assert "CC7.2" in unsatisfied  # no detection runs
    assert "CC7.5" in unsatisfied  # no completed regenerations


def test_report_reflects_real_activity(tmp_path):
    phantom = PhantomInstance(tmp_path / "state")
    phantom.init()
    phantom.write_user_file("notes.txt", "data")
    phantom.take_snapshot()
    phantom.regenerate(reason="test: evidence generation")

    report = phantom.compliance.generate()
    by_id = {c.control_id: c for c in report.controls}

    assert by_id["A1.2"].satisfied  # snapshot_taken
    assert by_id["CC7.3"].satisfied  # regeneration_triggered
    assert by_id["CC7.5"].satisfied  # regeneration_complete
    assert by_id["CC7.5"].event_count >= 1


def test_chaos_run_evidences_the_recovery_testing_control(tmp_path):
    """A1.3 is the one control the chaos suite exists to evidence; the
    event the control map looks for must actually be emitted.
    """
    phantom = PhantomInstance(tmp_path / "state")
    phantom.init()
    by_id = {c.control_id: c for c in phantom.compliance.generate().controls}
    assert not by_id["A1.3"].satisfied

    phantom.audit.append("chaos_suite_run", scenarios=6, passed=6, all_passed=True, seed=1)

    by_id = {c.control_id: c for c in phantom.compliance.generate().controls}
    assert by_id["A1.3"].satisfied


def test_report_always_carries_the_disclaimer(tmp_path):
    phantom = PhantomInstance(tmp_path / "state")
    phantom.init()

    report = phantom.compliance.generate()

    assert report.disclaimer == DISCLAIMER
    assert "NOT a certification" in report.summary()


def test_gaps_name_the_audit_log_integrity_asymmetry(tmp_path):
    """The audit log isn't hash-chained; the report must say so itself."""
    phantom = PhantomInstance(tmp_path / "state")
    phantom.init()

    report = phantom.compliance.generate()

    assert any("tamper-evident" in gap for gap in report.gaps)


def test_gaps_include_out_of_scope_criteria(tmp_path):
    phantom = PhantomInstance(tmp_path / "state")
    phantom.init()

    report = phantom.compliance.generate()

    assert any("CC6.x" in gap for gap in report.gaps)
    assert any("CC8.1" in gap for gap in report.gaps)


def test_broken_custody_chain_surfaces_as_a_gap(tmp_path):
    phantom = PhantomInstance(tmp_path / "state")
    phantom.init()
    phantom.write_user_file("notes.txt", "data")
    phantom.take_snapshot()
    phantom.regenerate(reason="test: produce evidence")

    entry = phantom.vault.entries()[0]
    (phantom.vault.root / entry.case_id / "artifacts" / "notes.txt").write_text("altered")

    report = phantom.compliance.generate()

    assert any("custody chain does not verify" in gap for gap in report.gaps)


def test_missing_policy_surfaces_as_a_gap(tmp_path):
    phantom = PhantomInstance(tmp_path / "state")
    phantom.init()

    report = phantom.compliance.generate()

    assert any("no regeneration cadence configured" in gap for gap in report.gaps)


def test_report_writes_json(tmp_path):
    import json

    phantom = PhantomInstance(tmp_path / "state")
    phantom.init()

    out = tmp_path / "reports" / "compliance.json"
    phantom.compliance.write(out)

    data = json.loads(out.read_text())
    assert data["disclaimer"] == DISCLAIMER
    assert "controls" in data and "gaps" in data
