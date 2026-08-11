"""Data Sanitization Layer (charter §5.E).

Phase 1 shipped a two-check placeholder and was explicit that it was not
this layer -- the risk register calls sanitization "a Phase 2 gate, not
optional," required "for safe scheduled restores" (§6 Phase 2). This is
that layer for the MVP: a small multi-signal scanning pipeline, closer to
how real restore-time AV/EDR stacks combine several weak signals instead
of trusting any single check.

Rules, in order:
  1. known_bad_hash_rule      -- exact match against a persisted blocklist,
                                  seeded by the attack simulator or an operator
  2. suspicious_filename_rule  -- ransom-note / lock-suffix naming patterns
  3. extension_mismatch_rule    -- magic-byte sniffing vs. the declared
                                  extension (an executable masquerading as a
                                  document)
  4. high_entropy_rule           -- Shannon entropy of content that claims to
                                  be plain/structured text; encrypted or
                                  packed payloads are high-entropy, ordinary
                                  text and config files aren't

This is still heuristic, not a production AV/ML engine -- there is no
substitute here for real signature and behavioral detection. What Phase 2
adds over Phase 1 is the pipeline shape (pluggable rules, findings with
severity, a persisted quarantine store an operator can review) that a real
engine slots into, plus enough real detection logic that the attack demo
isn't trivially defeated by a rename.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

Rule = Callable[[str, bytes], Optional["Finding"]]


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str  # "low" | "medium" | "high"
    reason: str


@dataclass
class SanitizeResult:
    clean: dict  # relpath -> content hash, safe to restore
    quarantined: dict  # relpath -> list[Finding]


def compute_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


# -- Rule 1: known-bad hash -------------------------------------------------

def known_bad_hash_rule(known_bad_hashes: set) -> Rule:
    def _rule(relpath: str, content: bytes) -> Optional[Finding]:
        digest = compute_hash(content)
        if digest in known_bad_hashes:
            return Finding("known_bad_hash", "high", f"content matches known-bad hash {digest[:12]}...")
        return None
    return _rule


# -- Rule 2: suspicious filename ---------------------------------------------

SUSPICIOUS_NAME_PATTERNS = [
    re.compile(r"(?i)ransom.*note"),
    re.compile(r"(?i)\.locked$"),
    re.compile(r"(?i)readme.*decrypt"),
]


def suspicious_filename_rule(relpath: str, content: bytes) -> Optional[Finding]:
    for pattern in SUSPICIOUS_NAME_PATTERNS:
        if pattern.search(relpath):
            return Finding("suspicious_filename", "medium", f"filename matches suspicious pattern {pattern.pattern!r}")
    return None


# -- Rule 3: extension / content-type mismatch -------------------------------

_MAGIC_SIGNATURES = [
    (b"MZ", "pe_executable"),
    (b"\x7fELF", "elf_executable"),
    (b"PK\x03\x04", "zip_or_office_archive"),
]
_EXECUTABLE_SIGNATURES = {"pe_executable", "elf_executable"}
_EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".so", ".bin", ".sys"}


def _sniff(content: bytes) -> Optional[str]:
    for magic, label in _MAGIC_SIGNATURES:
        if content.startswith(magic):
            return label
    return None


def extension_mismatch_rule(relpath: str, content: bytes) -> Optional[Finding]:
    sniffed = _sniff(content)
    if sniffed in _EXECUTABLE_SIGNATURES:
        ext = Path(relpath).suffix.lower()
        if ext not in _EXECUTABLE_EXTENSIONS:
            return Finding(
                "extension_mismatch", "high",
                f"content sniffs as {sniffed} but filename extension is {ext or '(none)'}",
            )
    return None


# -- Rule 4: high entropy where plain text/config is expected ----------------

_ENTROPY_THRESHOLD = 7.5  # bits/byte; random/encrypted data approaches 8.0
_ENTROPY_MIN_SIZE = 64  # entropy is meaningless noise on tiny samples
_TEXTUAL_EXTENSIONS = {".txt", ".csv", ".conf", ".md", ".json", ".ini", ".log", ".yaml", ".yml"}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def high_entropy_rule(relpath: str, content: bytes) -> Optional[Finding]:
    if len(content) < _ENTROPY_MIN_SIZE:
        return None
    ext = Path(relpath).suffix.lower()
    if ext not in _TEXTUAL_EXTENSIONS:
        return None
    entropy = shannon_entropy(content)
    if entropy >= _ENTROPY_THRESHOLD:
        return Finding(
            "high_entropy", "medium",
            f"{ext} file has {entropy:.2f} bits/byte entropy (>= {_ENTROPY_THRESHOLD}); "
            "looks encrypted/packed, not plain text",
        )
    return None


DEFAULT_RULES: list[Rule] = [suspicious_filename_rule, extension_mismatch_rule, high_entropy_rule]


# -- Pipeline -----------------------------------------------------------------

def scan(files: dict, known_bad_hashes: set = frozenset(), rules: list = None) -> SanitizeResult:
    """files: relpath -> raw content. A file is quarantined if ANY rule fires."""
    all_rules: list[Rule] = [known_bad_hash_rule(known_bad_hashes), *(rules if rules is not None else DEFAULT_RULES)]
    clean: dict = {}
    quarantined: dict = {}
    for relpath, content in files.items():
        findings = [f for f in (rule(relpath, content) for rule in all_rules) if f is not None]
        if findings:
            quarantined[relpath] = findings
        else:
            clean[relpath] = compute_hash(content)
    return SanitizeResult(clean=clean, quarantined=quarantined)


# -- Persistent blocklist (survives across separate CLI process invocations) -

class Blocklist:
    """On-disk known-bad-hash registry, seeded by the attack simulator."""

    def __init__(self, path: Path):
        self.path = path

    def load(self) -> set:
        if not self.path.exists():
            return set()
        return set(json.loads(self.path.read_text()))

    def register(self, content: bytes) -> str:
        digest = compute_hash(content)
        hashes = self.load()
        hashes.add(digest)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(sorted(hashes), indent=2))
        return digest


# -- Persistent quarantine store: what got blocked, and why, for review ------

class QuarantineStore:
    def __init__(self, root: Path):
        self.root = root

    def persist(self, batch_id: str, files: dict, result: SanitizeResult) -> Path:
        """Write quarantined content + a findings manifest under root/<batch_id>/."""
        batch_dir = self.root / batch_id
        manifest = {}
        for relpath, findings in result.quarantined.items():
            target = batch_dir / "files" / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(files[relpath])
            manifest[relpath] = [{"rule": f.rule, "severity": f.severity, "reason": f.reason} for f in findings]
        batch_dir.mkdir(parents=True, exist_ok=True)
        (batch_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
        return batch_dir
