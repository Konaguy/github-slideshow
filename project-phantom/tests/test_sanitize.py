from phantom.sanitize import Blocklist, QuarantineStore, compute_hash, scan


def test_clean_file_passes():
    result = scan({"notes.txt": b"quarterly numbers"})
    assert "notes.txt" in result.clean
    assert result.quarantined == {}


def test_known_bad_hash_is_quarantined():
    content = b"ransom payload"
    result = scan({"payload.bin": content}, known_bad_hashes={compute_hash(content)})
    assert "payload.bin" in result.quarantined
    assert result.quarantined["payload.bin"][0].rule == "known_bad_hash"
    assert result.clean == {}


def test_suspicious_filename_is_quarantined():
    result = scan({"RANSOM_NOTE_readme.txt": b"pay up"})
    assert "RANSOM_NOTE_readme.txt" in result.quarantined
    assert result.quarantined["RANSOM_NOTE_readme.txt"][0].rule == "suspicious_filename"


def test_executable_masquerading_as_document_is_quarantined():
    pe_header = b"MZ" + b"\x00" * 62  # minimal PE/DOS header magic
    result = scan({"invoice.pdf": pe_header})
    assert "invoice.pdf" in result.quarantined
    reasons = {f.rule for f in result.quarantined["invoice.pdf"]}
    assert "extension_mismatch" in reasons


def test_real_executable_with_matching_extension_is_not_flagged_by_extension_rule():
    pe_header = b"MZ" + b"\x00" * 62
    result = scan({"tool.exe": pe_header})
    # extension_mismatch shouldn't fire when the extension matches the sniffed type
    assert "tool.exe" not in result.quarantined


def test_high_entropy_text_file_is_quarantined():
    import os

    # A small random sample has biased (understated) empirical entropy --
    # use enough bytes that the measured value reliably clears the threshold.
    random_bytes = os.urandom(4096)
    result = scan({"notes.txt": random_bytes})
    assert "notes.txt" in result.quarantined
    reasons = {f.rule for f in result.quarantined["notes.txt"]}
    assert "high_entropy" in reasons


def test_low_entropy_text_file_is_not_flagged_by_entropy_rule():
    plain = ("the quick brown fox jumps over the lazy dog " * 5).encode()
    result = scan({"notes.txt": plain})
    assert "notes.txt" in result.clean


def test_blocklist_persists_across_instances(tmp_path):
    path = tmp_path / "known_bad_hashes.json"
    content = b"MZ-fake-payload-bytes"

    Blocklist(path).register(content)

    # A fresh Blocklist pointed at the same file (simulating a separate
    # CLI process) must see the hash registered by the first one.
    reloaded = Blocklist(path).load()
    assert compute_hash(content) in reloaded


def test_quarantine_store_persists_flagged_content_and_manifest(tmp_path):
    files = {"RANSOM_NOTE_readme.txt": b"pay up"}
    result = scan(files)

    store = QuarantineStore(tmp_path / "quarantine")
    batch_dir = store.persist("batch-1", files, result)

    assert (batch_dir / "files" / "RANSOM_NOTE_readme.txt").read_bytes() == b"pay up"
    manifest = (batch_dir / "manifest.json").read_text()
    assert "suspicious_filename" in manifest
