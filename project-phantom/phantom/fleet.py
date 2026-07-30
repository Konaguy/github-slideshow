"""Fleet Immunity & Threat-Intel Feed (charter §5.H).

§5.H: "Attack signatures propagate across all Phantom instances: fleet
pre-emptively hardens or regenerates. Aggregated, anonymized intel becomes
a sellable feed." §2 frames this as the network effect: "Every customer
attack becomes harvested threat intelligence... the product gets stronger
with each attack across the fleet." §4 sets the metric: time from first
detection to fleet-wide hardening < 15 minutes.

The loop implemented here: when one instance's detection engine flags an
attack, the indicators it saw (content hashes of the malicious arrivals)
are published to a shared feed. Every other instance pulls the feed and
folds those hashes into its own sanitize blocklist, so the same payload is
quarantined on arrival at instances that were never themselves attacked.

Anonymization: §9's risk register flags "threat-intel feed privacy
concerns," mitigated by "anonymization, customer opt-in, contractual data
boundaries." Published indicators carry the content hash and a coarse
label only -- never file contents, file paths, or customer identifiers.
`publish` takes an explicit `share` flag to model per-customer opt-in;
instances that don't opt in still *consume* the feed.

Scope caveat: this is a shared JSONL file standing in for what would be a
real distribution service (authenticated pub/sub, signed indicator
bundles, revocation, TTLs). The fleet here is several PhantomInstance
objects on one disk, not machines across a network.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Indicator:
    content_hash: str
    label: str
    published_at: str
    source_fingerprint: str  # anonymized: a rotating pseudonym, never a customer id


class ThreatIntelFeed:
    """Shared, append-only indicator feed consumed by every fleet instance."""

    def __init__(self, path: Path):
        self.path = path

    def indicators(self) -> list:
        if not self.path.exists():
            return []
        return [Indicator(**json.loads(line)) for line in self.path.read_text().splitlines() if line.strip()]

    def publish(self, content_hashes, label: str, source_fingerprint: str, share: bool = True) -> list:
        """Publish indicators to the fleet. `share=False` models a customer
        who has not opted into contributing (they still consume the feed).
        """
        if not share:
            return []
        known = {i.content_hash for i in self.indicators()}
        published = []
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as fh:
            for content_hash in sorted(set(content_hashes) - known):
                indicator = Indicator(
                    content_hash=content_hash,
                    label=label,
                    published_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    source_fingerprint=source_fingerprint,
                )
                fh.write(json.dumps(asdict(indicator)) + "\n")
                published.append(indicator)
        return published

    def hashes(self) -> set:
        return {i.content_hash for i in self.indicators()}
