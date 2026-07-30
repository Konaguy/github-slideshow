"""Placeholder restore-time quarantine gate.

The charter's risk register is explicit: "Sanitization layer is a Phase 2
gate, not optional" (§9), and the roadmap ships the real Data Sanitization
Layer (§5.E) in Phase 2, "required for safe scheduled restores." This
module is NOT that layer. It exists only so the Phase 1 attack -> regenerate
demo doesn't restore an attacker's payload verbatim, and to mark exactly
where the real scanning pipeline plugs in later.

Detection here is intentionally naive: a hash blocklist plus a couple of
filename heuristics. Do not extend this into production sanitization logic
-- build the real thing in Phase 2 instead.

The blocklist is passed in by the caller rather than kept as module state:
`attack` and `regen` are separate CLI process invocations, so anything
held only in a Python-level global would vanish between them. See
`Blocklist` for the on-disk version used by the CLI/orchestrator.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

SUSPICIOUS_NAME_PATTERNS = [
    re.compile(r"(?i)ransom.*note"),
    re.compile(r"(?i)\.locked$"),
    re.compile(r"(?i)readme.*decrypt"),
]


@dataclass
class SanitizeResult:
    clean: dict  # relpath -> content hash, safe to restore
    quarantined: dict  # relpath -> reason


def compute_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def scan(files: dict[str, bytes], known_bad_hashes: set[str] = frozenset()) -> SanitizeResult:
    """files: relpath -> raw content. Returns which are safe vs quarantined."""
    clean: dict[str, str] = {}
    quarantined: dict[str, str] = {}
    for relpath, content in files.items():
        digest = compute_hash(content)
        if digest in known_bad_hashes:
            quarantined[relpath] = f"content matches known-bad hash {digest[:12]}..."
            continue
        if any(pattern.search(relpath) for pattern in SUSPICIOUS_NAME_PATTERNS):
            quarantined[relpath] = "filename matches suspicious pattern"
            continue
        clean[relpath] = digest
    return SanitizeResult(clean=clean, quarantined=quarantined)


class Blocklist:
    """On-disk known-bad-hash registry, seeded by the attack simulator."""

    def __init__(self, path: Path):
        self.path = path

    def load(self) -> set[str]:
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
