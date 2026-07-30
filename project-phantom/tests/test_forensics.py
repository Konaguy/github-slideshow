import json

from phantom.forensics import ForensicVault


def _evidence_dir(tmp_path, name, content="incriminating"):
    source = tmp_path / name
    source.mkdir(parents=True, exist_ok=True)
    (source / "payload.txt").write_text(content)
    return source


def test_capture_records_chain_of_custody_metadata(tmp_path):
    vault = ForensicVault(tmp_path / "vault")
    entry = vault.capture(_evidence_dir(tmp_path, "src1"), reason="detection: score 0.90", custodian="phantom-vm-0")

    assert entry.sequence == 0
    assert entry.reason == "detection: score 0.90"
    assert entry.custodian == "phantom-vm-0"
    assert entry.prev_hash == "0" * 64
    assert (vault.root / entry.case_id / "artifacts" / "payload.txt").read_text() == "incriminating"


def test_chain_links_entries_and_verifies(tmp_path):
    vault = ForensicVault(tmp_path / "vault")
    first = vault.capture(_evidence_dir(tmp_path, "src1", "one"), reason="first")
    second = vault.capture(_evidence_dir(tmp_path, "src2", "two"), reason="second")

    assert second.prev_hash == first.entry_hash
    assert second.sequence == 1
    assert vault.verify_chain() == []


def test_tampering_with_stored_artifacts_is_detected(tmp_path):
    vault = ForensicVault(tmp_path / "vault")
    entry = vault.capture(_evidence_dir(tmp_path, "src1"), reason="first")
    assert vault.verify_chain() == []

    # Someone edits the evidence after the fact.
    (vault.root / entry.case_id / "artifacts" / "payload.txt").write_text("sanitized version")

    problems = vault.verify_chain()
    assert any("do not match recorded digest" in p for p in problems)


def test_tampering_with_ledger_entry_is_detected(tmp_path):
    vault = ForensicVault(tmp_path / "vault")
    vault.capture(_evidence_dir(tmp_path, "src1"), reason="first")

    # Rewrite the recorded reason without recomputing the hash.
    lines = vault.ledger_path.read_text().splitlines()
    record = json.loads(lines[0])
    record["reason"] = "routine maintenance"
    vault.ledger_path.write_text(json.dumps(record) + "\n")

    problems = vault.verify_chain()
    assert any("does not match its own contents" in p for p in problems)


def test_removing_a_middle_entry_breaks_the_chain(tmp_path):
    vault = ForensicVault(tmp_path / "vault")
    vault.capture(_evidence_dir(tmp_path, "src1", "one"), reason="first")
    vault.capture(_evidence_dir(tmp_path, "src2", "two"), reason="second")
    vault.capture(_evidence_dir(tmp_path, "src3", "three"), reason="third")
    assert vault.verify_chain() == []

    # Excise the middle entry -- the classic "make the incident disappear" move.
    lines = vault.ledger_path.read_text().splitlines()
    vault.ledger_path.write_text(lines[0] + "\n" + lines[2] + "\n")

    problems = vault.verify_chain()
    assert problems  # sequence gap and/or broken prev_hash link
    assert any("prev_hash" in p or "sequence" in p for p in problems)


def test_missing_artifacts_are_detected(tmp_path):
    import shutil

    vault = ForensicVault(tmp_path / "vault")
    entry = vault.capture(_evidence_dir(tmp_path, "src1"), reason="first")

    shutil.rmtree(vault.root / entry.case_id / "artifacts")

    problems = vault.verify_chain()
    assert any("artifacts missing" in p for p in problems)


def test_capture_of_nonexistent_source_still_records_an_entry(tmp_path):
    """An instance destroyed before any data was written is still a case."""
    vault = ForensicVault(tmp_path / "vault")
    entry = vault.capture(tmp_path / "does-not-exist", reason="empty instance")

    assert entry.sequence == 0
    assert vault.verify_chain() == []
