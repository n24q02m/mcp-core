"""Pluggable credential backends.

A backend stores and retrieves OPAQUE ciphertext blobs keyed by a string.
Encryption and key derivation live in PerPluginStore; backends never see
plaintext. This seam lets MCP servers run serverless (e.g. Cloudflare Workers
KV) while stdio/VM deployments keep the on-disk layout via LocalFsBackend.
"""

from __future__ import annotations

import os
from pathlib import Path
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


def _key_to_path(key: str) -> Path:
    """Map a backend key to its on-disk path.

    "<plugin>/config"            -> ~/.<plugin>-mcp/config.json
    "<plugin>/subs/<sub>/config" -> ~/.<plugin>-mcp/subs/<sub>/config.json
    """
    plugin, _, rest = key.partition("/")
    base = Path.home() / f".{plugin}-mcp"
    if rest == "config":
        return base / "config.json"
    if rest.startswith("subs/") and rest.endswith("/config"):
        sub = rest[len("subs/") : -len("/config")]
        return base / "subs" / sub / "config.json"
    raise ValueError(f"Invalid backend key: {key}")


class LocalFsBackend:
    """Stores blobs on local disk, preserving the per-plugin layout."""

    def get(self, key: str) -> Optional[bytes]:
        path = _key_to_path(key)
        if not path.exists():
            return None
        return path.read_bytes()

    def put(self, key: str, blob: bytes) -> None:
        path = _key_to_path(key)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(blob)
        if os.name != "nt":
            os.chmod(path, 0o600)

    def delete(self, key: str) -> None:
        path = _key_to_path(key)
        if path.exists():
            path.unlink()
