"""Pluggable credential backends.

A backend stores and retrieves OPAQUE ciphertext blobs keyed by a string.
Encryption and key derivation live in PerPluginStore; backends never see
plaintext. This seam lets MCP servers run serverless (e.g. Cloudflare Workers
KV) while stdio/VM deployments keep the on-disk layout via LocalFsBackend.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class CredentialBackend(Protocol):
    """Stores opaque ciphertext blobs keyed by a string."""

    def get(self, key: str) -> Optional[bytes]: ...

    def put(self, key: str, blob: bytes) -> None: ...

    def delete(self, key: str) -> None: ...


class InMemoryBackend:
    """Dict-backed backend, primarily for tests."""

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}

    def get(self, key: str) -> Optional[bytes]:
        return self._store.get(key)

    def put(self, key: str, blob: bytes) -> None:
        self._store[key] = blob

    def delete(self, key: str) -> None:
        self._store.pop(key, None)
