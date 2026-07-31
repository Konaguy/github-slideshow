import re

from phantom.dashboard import DashboardData, collect, esc, render, render_to_file
from phantom.orchestrator import PhantomInstance


def _instance(tmp_path, name="phantom_state"):
    phantom = PhantomInstance(tmp_path / name)
    phantom.init()
    return phantom


# -- escaping: the security-critical property ---------------------------------

def test_esc_neutralizes_markup_and_quotes():
    assert esc('<script>alert(1)</script>') == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert esc('" onload="x') == "&quot; onload=&quot;x"


def test_attacker_chosen_filename_cannot_inject_markup(tmp_path):
    """A quarantined filename is attacker-controlled and lands in the console
    an incident responder reads. It must never render as live markup.
    """
    phantom = _instance(tmp_path)
    payload_name = '<img src=x onerror=alert(1)>.txt'
    phantom.write_user_file("notes.txt", "ordinary")
    phantom.take_snapshot()

    # Plant a file whose *name* is the attack, and blocklist its content so
    # the sanitizer holds it and the console has to display the name.
    content = "ransom instructions"
    phantom.blocklist.register(content.encode())
    phantom.write_user_file(payload_name, content)
    phantom.take_snapshot()
    phantom.regenerate(reason="test: injection attempt")

    html = render(collect(phantom))

    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_audit_reason_is_escaped(tmp_path):
    phantom = _instance(tmp_path)
    phantom.write_user_file("a.txt", "x")
    phantom.take_snapshot()
    phantom.regenerate(reason='</td><script>alert(1)</script>')

    html = render(collect(phantom))

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# -- honest empty states ------------------------------------------------------

def test_fresh_instance_says_so_instead_of_faking_zeros(tmp_path):
    phantom = _instance(tmp_path)
    html = render(collect(phantom))

    assert "No regenerations recorded yet." in html
    assert "Nothing quarantined." in html
    assert "No evidence captured yet." in html
    # The RTO tile must not claim a passing 0.00s when nothing has run.
    assert "no regeneration recorded yet" in html


# -- real state makes it into the page ----------------------------------------

def test_regenerations_are_reconstructed_from_the_audit_log(tmp_path):
    phantom = _instance(tmp_path)
    phantom.write_user_file("a.txt", "x")
    phantom.take_snapshot()
    phantom.regenerate(reason="first rebuild")
    phantom.regenerate(reason="second rebuild")

    data = collect(phantom)

    assert len(data.regenerations) == 2
    assert [r.sequence for r in data.regenerations] == [1, 2]
    assert data.regenerations[0].reason == "first rebuild"
    assert data.regenerations[1].reason == "second rebuild"
    assert all(r.rto_seconds >= 0 for r in data.regenerations)


def test_provider_outage_is_reflected_in_posture_and_list(tmp_path):
    phantom = _instance(tmp_path)
    down = phantom.backup.providers[0].name
    phantom.backup.set_outage(down, down=True)

    html = render(collect(phantom))

    assert esc(down) in html
    assert "simulated outage" in html
    assert "providers degraded" in html


def test_quarantined_findings_are_listed_with_rule_and_severity(tmp_path):
    phantom = _instance(tmp_path)
    phantom.write_user_file("keep.txt", "ordinary text")
    phantom.take_snapshot()
    phantom.simulate_attack()
    phantom.take_snapshot()
    report = phantom.regenerate(reason="test: quarantine")

    assert report.files_quarantined >= 1
    data = collect(phantom)
    html = render(data)

    assert data.quarantine_batches, "a quarantine batch should have been persisted"
    assert "RANSOM_NOTE_README.txt" in html
    assert "known_bad_hash" in html or "suspicious_filename" in html


def test_broken_custody_chain_is_surfaced_as_critical(tmp_path):
    phantom = _instance(tmp_path)
    phantom.write_user_file("a.txt", "x")
    phantom.take_snapshot()
    phantom.simulate_attack()
    phantom.take_snapshot()
    phantom.regenerate(reason="test: evidence")

    # Tamper with a stored artifact so the ledger no longer verifies.
    artifacts = list((phantom.vault.root).rglob("*"))
    target = next(p for p in artifacts if p.is_file() and p.suffix == ".txt")
    target.write_text("tampered")

    html = render(collect(phantom))

    assert "Chain verification failed" in html
    assert "Chain of custody broken" in html


# -- output shape -------------------------------------------------------------

def test_page_is_self_contained_and_theme_aware(tmp_path):
    phantom = _instance(tmp_path)
    html = render(collect(phantom))

    assert html.startswith("<!doctype html>")
    # No external resources -- a console that phones home is a liability.
    assert "http://" not in html and "https://" not in html
    assert "<script" not in html.lower()
    assert "prefers-color-scheme: dark" in html
    assert '[data-theme="dark"]' in html


def test_wide_tables_scroll_rather_than_breaking_the_page(tmp_path):
    phantom = _instance(tmp_path)
    phantom.write_user_file("a.txt", "x")
    phantom.take_snapshot()
    phantom.regenerate(reason="test")

    html = render(collect(phantom))
    assert "overflow-x:auto" in html.replace(" ", "")


def test_failed_recovery_is_marked_by_shape_not_colour_alone(tmp_path):
    """Pass/fail must survive colour-blindness and greyscale printing."""
    phantom = _instance(tmp_path)
    phantom.write_user_file("a.txt", "x")
    phantom.take_snapshot()
    phantom.regenerate(reason="test")

    data = collect(phantom)
    data.regenerations[0].rto_pass = False  # force a miss
    html = render(data)

    assert "bar-flag" in html, "a failing rebuild needs a non-colour marker"
    assert "&#10007;" in html


def test_render_to_file_writes_utf8(tmp_path):
    phantom = _instance(tmp_path)
    out = render_to_file(phantom, tmp_path / "nested" / "console.html")

    assert out.exists()
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_compliance_failure_does_not_take_the_console_down(tmp_path):
    """A reporting bug must not make the console unrenderable."""
    phantom = _instance(tmp_path)

    class Broken:
        def generate(self):
            raise RuntimeError("control evaluation exploded")

    phantom.compliance = Broken()

    html = render(collect(phantom))
    assert "No compliance report available." in html
