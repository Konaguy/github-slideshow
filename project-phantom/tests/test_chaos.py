import itertools

from phantom.chaos import ChaosRunner, ScenarioResult, check_invariants
from phantom.orchestrator import PhantomInstance


def _runner(tmp_path, seed=1234):
    counter = itertools.count()

    def make_instance():
        return PhantomInstance(tmp_path / f"run-{next(counter):03d}")

    return ChaosRunner(make_instance, seed=seed)


def test_full_chaos_suite_passes(tmp_path):
    """Every recovery invariant must survive every injected fault."""
    report = _runner(tmp_path).run_all()

    assert report.passed, report.summary()
    assert len(report.results) == len(ChaosRunner.ALL_SCENARIOS)


def test_provider_outage_scenario_recovers(tmp_path):
    result = _runner(tmp_path).scenario_provider_outage()
    assert result.passed, result.summary()


def test_majority_outage_still_recovers(tmp_path):
    result = _runner(tmp_path).scenario_majority_provider_outage()
    assert result.passed, result.summary()


def test_attack_during_outage_recovers_without_restoring_malware(tmp_path):
    result = _runner(tmp_path).scenario_attack_then_outage()
    assert result.passed, result.summary()


def test_baseline_drift_scenario_expects_a_refusal(tmp_path):
    """Spawning from a tampered baseline is a failure, not a recovery."""
    result = _runner(tmp_path).scenario_baseline_drift()
    assert result.passed, result.summary()
    assert "refused" in result.detail


def test_vault_tampering_scenario_detects_tampering(tmp_path):
    result = _runner(tmp_path).scenario_vault_tampering_detected()
    assert result.passed, result.summary()


def test_randomized_scenario_is_reproducible_with_a_seed(tmp_path):
    first = _runner(tmp_path / "a", seed=42).scenario_random_multi_outage()
    second = _runner(tmp_path / "b", seed=42).scenario_random_multi_outage()
    assert first.detail == second.detail


def test_scenario_crash_is_reported_as_a_failure_not_a_suite_crash(tmp_path):
    """A scenario that raises must fail loudly, not abort the whole run."""
    runner = _runner(tmp_path)

    def exploding_scenario():
        raise RuntimeError("storage layer went sideways")

    runner.scenario_provider_outage = exploding_scenario
    report = runner.run_all()

    assert not report.passed
    crashed = [r for r in report.results if "sideways" in r.detail]
    assert len(crashed) == 1
    assert not crashed[0].passed


def test_check_invariants_flags_a_missing_restored_file(tmp_path):
    phantom = PhantomInstance(tmp_path / "state")
    phantom.init()
    phantom.write_user_file("notes.txt", "expected content")
    phantom.take_snapshot()
    report = phantom.regenerate(reason="test")

    violations = check_invariants(phantom, report, {"absent.txt": "never existed"})

    assert any("was not restored" in v for v in violations)


def test_check_invariants_flags_a_missing_report():
    violations = check_invariants(phantom=None, report=None, expected_files={})
    assert violations == ["regeneration did not complete"]


def test_scenario_result_summary_lists_violations():
    result = ScenarioResult(name="demo", passed=False, detail="broke", violations=["RTO exceeded"])
    assert "FAIL" in result.summary()
    assert "RTO exceeded" in result.summary()
