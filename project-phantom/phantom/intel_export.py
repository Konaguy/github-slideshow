"""Threat-intel feed productization (charter §6 Phase 4, §5.H, §2).

Phase 3 built the internal feed that makes the fleet immune to each
other's attacks. Phase 4 is where that becomes something you can hand to
someone outside the fleet: §2 calls the aggregated, anonymized intel a
network effect, §5.H says it "becomes a sellable feed," and §10 leaves
open whether it ships "internal-only initially, or a sellable product
from day one."

What productizing actually requires, versus what Phase 3 had:

  Phase 3 (internal)          Phase 4 (subscriber-facing)
  -------------------          ----------------------------
  append-only JSONL            versioned, self-describing bundle
  indicators live forever      per-indicator TTL, expired ones filtered out
  no way to retract            revocation list, applied at export
  implicit trust               integrity digest over the bundle
  one consumer                 tiers, so a free feed != the paid feed

Tiering maps to the charter's product tiers (§3): "Phantom Intel" is the
tier that includes the "cross-fleet threat-intel feed," so the full
bundle is INTEL. A COMMUNITY tier carries a reduced set -- this is a
packaging decision, not a security one, and the split here (recent
indicators only) is a placeholder for whatever commercial policy the
business actually lands on.

Not implemented -- deliberately:
  - Real signing. `integrity_digest` proves a bundle wasn't corrupted in
    transit; it does NOT prove who issued it, because anyone can
    recompute a plain digest over modified content. Authenticity needs an
    asymmetric signature over the bundle with a published issuer key
    (and key rotation, and revocation of the signing key itself). The
    digest field is where that signature attaches; treat the current
    value as a checksum, not a provenance claim.
  - Distribution: authenticated pub/sub, subscriber identity, rate
    limiting, billing. Bundles here are written to a file.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

BUNDLE_FORMAT_VERSION = "1.0"
DEFAULT_TTL_SECONDS = 90 * 24 * 60 * 60  # 90 days

# Tier -> how many days of indicators that tier receives. None = everything.
TIER_WINDOW_DAYS = {
    "intel": None,
    "community": 7,
}


@dataclass
class ExportedIndicator:
    content_hash: str
    label: str
    published_at: str
    expires_at: str


@dataclass
class IntelBundle:
    format_version: str
    tier: str
    generated_at: str
    indicator_count: int
    indicators: list
    integrity_digest: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


class RevocationList:
    """Indicators withdrawn after publication -- a false positive that
    burned a subscriber, or intel pulled for legal reasons.
    """

    def __init__(self, path: Path):
        self.path = path

    def load(self) -> set:
        if not self.path.exists():
            return set()
        return set(json.loads(self.path.read_text()))

    def revoke(self, content_hash: str) -> None:
        revoked = self.load()
        revoked.add(content_hash)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(sorted(revoked), indent=2))

    def unrevoke(self, content_hash: str) -> None:
        revoked = self.load()
        revoked.discard(content_hash)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(sorted(revoked), indent=2))


def _parse_ts(ts: str) -> float:
    return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))


def _format_ts(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def compute_integrity_digest(indicators: list) -> str:
    """Checksum over bundle contents. See module docstring: not a signature."""
    digest = hashlib.sha256()
    for indicator in sorted(indicators, key=lambda i: i.content_hash):
        digest.update(f"{indicator.content_hash}|{indicator.label}|{indicator.expires_at}".encode())
    return digest.hexdigest()


class IntelExporter:
    def __init__(self, feed, revocations: RevocationList, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.feed = feed
        self.revocations = revocations
        self.ttl_seconds = ttl_seconds

    def export(self, tier: str = "intel", now: Optional[float] = None) -> IntelBundle:
        """Build a subscriber-facing bundle: TTL-filtered, revocation-filtered, tiered."""
        if tier not in TIER_WINDOW_DAYS:
            raise ValueError(f"unknown tier {tier!r}; expected one of {sorted(TIER_WINDOW_DAYS)}")

        now = now if now is not None else time.time()
        revoked = self.revocations.load()
        window_days = TIER_WINDOW_DAYS[tier]
        window_start = None if window_days is None else now - window_days * 24 * 60 * 60

        exported = []
        for indicator in self.feed.indicators():
            if indicator.content_hash in revoked:
                continue
            published_epoch = _parse_ts(indicator.published_at)
            expires_epoch = published_epoch + self.ttl_seconds
            if expires_epoch <= now:
                continue  # expired
            if window_start is not None and published_epoch < window_start:
                continue  # outside this tier's window
            exported.append(ExportedIndicator(
                content_hash=indicator.content_hash,
                label=indicator.label,
                published_at=indicator.published_at,
                expires_at=_format_ts(expires_epoch),
            ))

        return IntelBundle(
            format_version=BUNDLE_FORMAT_VERSION,
            tier=tier,
            generated_at=_format_ts(now),
            indicator_count=len(exported),
            indicators=[asdict(i) for i in exported],
            integrity_digest=compute_integrity_digest(exported),
        )

    def export_to_file(self, path: Path, tier: str = "intel", now: Optional[float] = None) -> IntelBundle:
        bundle = self.export(tier=tier, now=now)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(bundle.to_json())
        return bundle


def verify_bundle(bundle_json: str) -> list:
    """Subscriber-side check: does the bundle match its own digest?

    Detects corruption/truncation in transit. Does NOT authenticate the
    issuer -- see the module docstring.
    """
    problems = []
    try:
        data = json.loads(bundle_json)
    except json.JSONDecodeError as exc:
        return [f"bundle is not valid JSON: {exc}"]

    if data.get("format_version") != BUNDLE_FORMAT_VERSION:
        problems.append(
            f"unsupported format_version {data.get('format_version')!r} (expected {BUNDLE_FORMAT_VERSION})"
        )

    indicators = [ExportedIndicator(**i) for i in data.get("indicators", [])]
    if len(indicators) != data.get("indicator_count"):
        problems.append(
            f"indicator_count is {data.get('indicator_count')} but bundle carries {len(indicators)}"
        )
    if compute_integrity_digest(indicators) != data.get("integrity_digest"):
        problems.append("integrity_digest does not match bundle contents (corrupted or modified)")

    return problems
