"""Initial multi-cloud storage abstraction + multi-region failover.

Charter §6 Phase 2: "Multi-region failover and initial multi-cloud storage
abstraction." (The full multi-cloud control plane -- §5.K -- is a Phase 3
deliverable; this is deliberately just the storage-layer piece of it.)

There are no real cloud credentials available in this environment, so
every provider here is still local-disk-backed. What Phase 2 actually adds
is the shape: a `StorageProvider` interface that a real S3/Azure
Blob/GCS backend could implement without any caller changes, named
providers standing in for specific regions/clouds, fan-out replication on
write, and failover on read when a provider is unavailable.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol


class ProviderUnavailable(RuntimeError):
    """Raised when a provider can't be reached (real outage or `set_outage`)."""


class StorageProvider(Protocol):
    name: str

    def put(self, digest: str, content: bytes) -> None: ...
    def get(self, digest: str) -> bytes: ...
    def has(self, digest: str) -> bool: ...
    def is_available(self) -> bool: ...


class LocalDiskProvider:
    """A storage provider backed by a local directory.

    Stands in for one cloud region/provider. An `.outage` marker file
    simulates the provider being unreachable, so failover can be
    demonstrated and tested deterministically without a real network
    partition -- see `set_outage`.
    """

    def __init__(self, name: str, root: Path):
        self.name = name
        self.root = root
        self.objects_dir = root / "objects"
        self._outage_marker = root / ".outage"

    def is_available(self) -> bool:
        return not self._outage_marker.exists()

    def set_outage(self, down: bool) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if down:
            self._outage_marker.write_text("simulated outage\n")
        elif self._outage_marker.exists():
            self._outage_marker.unlink()

    def _check_available(self) -> None:
        if not self.is_available():
            raise ProviderUnavailable(f"provider {self.name!r} is unavailable")

    def put(self, digest: str, content: bytes) -> None:
        self._check_available()
        self.objects_dir.mkdir(parents=True, exist_ok=True)
        blob_path = self.objects_dir / digest
        if not blob_path.exists():
            blob_path.write_bytes(content)

    def get(self, digest: str) -> bytes:
        self._check_available()
        return (self.objects_dir / digest).read_bytes()

    def has(self, digest: str) -> bool:
        self._check_available()
        return (self.objects_dir / digest).exists()


class MultiRegionStore:
    """Fans writes out to every configured provider; reads fail over across
    providers in priority order. This is the "multi-region immutable
    storage" backing the snapshot engine's blob storage.
    """

    def __init__(self, providers: list):
        if not providers:
            raise ValueError("MultiRegionStore needs at least one provider")
        self.providers = providers

    def put(self, digest: str, content: bytes) -> list:
        """Write to every available provider. Returns provider names written to.

        Raises ProviderUnavailable only if EVERY provider is down --
        partial replication (degraded but not lost) is allowed through.
        """
        written = []
        for provider in self.providers:
            try:
                provider.put(digest, content)
                written.append(provider.name)
            except ProviderUnavailable:
                continue
        if not written:
            raise ProviderUnavailable(
                f"all providers unavailable, cannot store {digest[:12]}...: "
                f"{[p.name for p in self.providers]}"
            )
        return written

    def get(self, digest: str) -> tuple:
        """Read from the first available provider that has the object.

        Returns (content, provider_name_it_was_served_from) so callers can
        tell when a failover happened.
        """
        for provider in self.providers:
            try:
                if provider.has(digest):
                    return provider.get(digest), provider.name
            except ProviderUnavailable:
                continue
        raise ProviderUnavailable(f"object {digest[:12]}... not retrievable from any provider")

    def has_any(self, digest: str) -> bool:
        for provider in self.providers:
            try:
                if provider.has(digest):
                    return True
            except ProviderUnavailable:
                continue
        return False
