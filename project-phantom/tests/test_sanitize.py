from phantom.sanitize import Blocklist, compute_hash, scan


def test_clean_file_passes():
    result = scan({"notes.txt": b"quarterly numbers"})
    assert "notes.txt" in result.clean
    assert result.quarantined == {}


def test_known_bad_hash_is_quarantined():
    content = b"ransom payload"
    result = scan({"payload.bin": content}, known_bad_hashes={compute_hash(content)})
    assert "payload.bin" in result.quarantined
    assert result.clean == {}


def test_suspicious_filename_is_quarantined():
    result = scan({"RANSOM_NOTE_readme.txt": b"pay up"})
    assert "RANSOM_NOTE_readme.txt" in result.quarantined


def test_blocklist_persists_across_instances(tmp_path):
    path = tmp_path / "known_bad_hashes.json"
    content = b"MZ-fake-payload-bytes"

    Blocklist(path).register(content)

    # A fresh Blocklist pointed at the same file (simulating a separate
    # CLI process) must see the hash registered by the first one.
    reloaded = Blocklist(path).load()
    assert compute_hash(content) in reloaded
