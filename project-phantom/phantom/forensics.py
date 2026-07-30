"""Forensic Vault with chain-of-custody (charter §5.F).

§5.F: "On attack trigger, infected instance is snapshotted into an
isolated evidence vault before destruction. Chain-of-custody metadata for
legal/insurance use." §1.1 step 3 adds that Phantom "treats incidents as
evidence-generating moments, not just cleanup events."

Phases 1-2 copied the compromised data directory into `evidence/<ts>/`
before destroying the instance. That preserved the bytes but proved
nothing about them: an evidence copy that can be silently edited afterward
is not evidence. This module adds the integrity property that makes the
artifacts defensible -- a hash-chained ledger where each entry commits to
the entry before it, so altering or removing any past entry invalidates
every entry after it.

  entry_hash = sha256(sequence || captured_at || case_id || reason ||
                      custodian || content_digest || prev_hash)

`verify_chain()` recomputes the whole chain and re-hashes the stored
artifacts, so both ledger tampering and artifact tampering are detectable.

Scope caveats -- this is an integrity ledger, not a legal chain of custody:
a real deployment needs the vault on genuinely isolated,
write-once/WORM storage with independent access control (this writes to
the same local disk as everything else), plus signed timestamps from a
trusted authority rather than local clock reads, and per-custodian
cryptographic signatures rather than a name string. Those are deployment
and PKI concerns beyond this prototype; the ledger format here is what
they would attach to.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

LEDGER_NAME = "chain_of_custody.jsonl"
GENESIS_HASH = "0" * 64


@dataclass
class CustodyEntry:
    sequence: int
    captured_at: str
    case_id: str
    reason: str
    custodian: str
    content_digest: str  # digest over the captured artifact tree
    prev_hash: str
    entry_hash: str


def _hash_tree(root: Path) -> str:
    """Order-independent digest over every file in a directory tree."""
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _compute_entry_hash(sequence, captured_at, case_id, reason, custodian, content_digest, prev_hash) -> str:
    payload = "|".join([str(sequence), captured_at, case_id, reason, custodian, content_digest, prev_hash])
    return hashlib.sha256(payload.encode()).hexdigest()


class ForensicVault:
    """Append-only, hash-chained evidence store, isolated from the backup store."""

    def __init__(self, root: Path):
        self.root = root
        self.ledger_path = root / LEDGER_NAME

    # -- ledger ------------------------------------------------------

    def entries(self) -> list:
        if not self.ledger_path.exists():
            return []
        return [CustodyEntry(**json.loads(line)) for line in self.ledger_path.read_text().splitlines() if line.strip()]

    def _append_entry(self, entry: CustodyEntry) -> None:
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with self.ledger_path.open("a") as fh:
            fh.write(json.dumps(asdict(entry)) + "\n")

    # -- capture -----------------------------------------------------

    def capture(self, source_dir: Path, reason: str, custodian: str = "phantom-orchestrator",
                case_id: Optional[str] = None) -> CustodyEntry:
        """Copy `source_dir` into the vault and commit it to the custody chain."""
        existing = self.entries()
        sequence = len(existing)
        prev_hash = existing[-1].entry_hash if existing else GENESIS_HASH
        captured_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # Case ids become directory names -- keep them filesystem-safe (no colons).
        case_id = case_id or f"CASE-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{sequence:04d}"

        artifact_dir = self.root / case_id / "artifacts"
        artifact_dir.parent.mkdir(parents=True, exist_ok=True)
        if source_dir.exists():
            shutil.copytree(source_dir, artifact_dir, dirs_exist_ok=True)
        else:
            artifact_dir.mkdir(parents=True, exist_ok=True)

        content_digest = _hash_tree(artifact_dir)
        entry = CustodyEntry(
            sequence=sequence,
            captured_at=captured_at,
            case_id=case_id,
            reason=reason,
            custodian=custodian,
            content_digest=content_digest,
            prev_hash=prev_hash,
            entry_hash=_compute_entry_hash(
                sequence, captured_at, case_id, reason, custodian, content_digest, prev_hash
            ),
        )
        self._append_entry(entry)
        return entry

    # -- verification -------------------------------------------------

    def verify_chain(self) -> list:
        """Recompute the chain and re-hash stored artifacts.

        Returns a list of human-readable problems; empty means intact.
        """
        problems = []
        prev_hash = GENESIS_HASH
        for index, entry in enumerate(self.entries()):
            if entry.sequence != index:
                problems.append(f"entry {index}: sequence is {entry.sequence}, expected {index} (entry removed?)")
            if entry.prev_hash != prev_hash:
                problems.append(f"entry {index} ({entry.case_id}): prev_hash does not match preceding entry")

            expected_hash = _compute_entry_hash(
                entry.sequence, entry.captured_at, entry.case_id, entry.reason,
                entry.custodian, entry.content_digest, entry.prev_hash,
            )
            if entry.entry_hash != expected_hash:
                problems.append(f"entry {index} ({entry.case_id}): entry_hash does not match its own contents (tampered)")

            artifact_dir = self.root / entry.case_id / "artifacts"
            if not artifact_dir.exists():
                problems.append(f"entry {index} ({entry.case_id}): artifacts missing from vault")
            elif _hash_tree(artifact_dir) != entry.content_digest:
                problems.append(f"entry {index} ({entry.case_id}): artifacts do not match recorded digest (tampered)")

            prev_hash = entry.entry_hash
        return problems
