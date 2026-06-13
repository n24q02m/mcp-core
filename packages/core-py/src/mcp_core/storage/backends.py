"""Pluggable credential backends.

A backend stores and retrieves OPAQUE ciphertext blobs keyed by a string.
Encryption and key derivation live in PerPluginStore; backends never see
plaintext. This seam lets MCP servers run serverless (e.g. Cloudflare Workers
KV) while stdio/VM deployments keep the on-disk layout via LocalFsBackend.
"""

from __future__ import annotations

import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable
from urllib.parse import quote


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


def _validate_component(name: str) -> str:
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
        raise ValueError(f"Invalid path component: {name!r}")
    return name


def _key_to_path(key: str) -> Path:
    """Map a backend key to its on-disk path.

    "<plugin>/config"            -> ~/.<plugin>-mcp/config.json
    "<plugin>/subs/<sub>/config" -> ~/.<plugin>-mcp/subs/<sub>/config.json
    """
    plugin, _, rest = key.partition("/")
    _validate_component(plugin)
    base = Path.home() / f".{plugin}-mcp"
    if rest == "config":
        path = base / "config.json"
    elif rest.startswith("subs/") and rest.endswith("/config"):
        sub = rest[len("subs/") : -len("/config")]
        _validate_component(sub)
        path = base / "subs" / sub / "config.json"
    else:
        raise ValueError(f"Invalid backend key: {key}")

    # Defense-in-depth: _validate_component already rejects separators/./../empty/NUL.
    base_resolved = base.resolve()
    resolved = path.resolve()
    if base_resolved != resolved and base_resolved not in resolved.parents:
        raise ValueError(f"Path escapes base: {key}")
    return path


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


class _UrllibHttp:
    """Minimal HTTP client over urllib, returning (status, body)."""

    def request(self, method: str, url: str, data: Optional[bytes], headers: dict) -> tuple[int, bytes]:
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                return (resp.status, resp.read())
        except urllib.error.HTTPError as exc:
            return (exc.code, b"")


class CfKvBackend:
    """Stores blobs in a Cloudflare Workers KV namespace over HTTP.

    Error contract: 200 -> data, 404 -> absent (None for get, no-op for delete).
    Every other HTTP status, plus transport errors (URLError / socket errors from
    the HTTP client), raises -- failures are loud, never silently returned as data.
    """

    def __init__(self, base_url: str, token: Optional[str] = None, http=None) -> None:
        self._base_url = base_url
        self._token = token
        self._http = http if http is not None else _UrllibHttp()

    def _url(self, key: str) -> str:
        return self._base_url.rstrip("/") + "/" + quote(key, safe="")

    def _headers(self) -> dict:
        if self._token:
            return {"Authorization": f"Bearer {self._token}"}
        return {}

    def get(self, key: str) -> Optional[bytes]:
        status, body = self._http.request("GET", self._url(key), None, self._headers())
        if status == 200:
            return body
        if status == 404:
            return None
        raise RuntimeError(f"CfKvBackend get failed: HTTP {status}")

    def put(self, key: str, blob: bytes) -> None:
        status, _ = self._http.request("PUT", self._url(key), blob, self._headers())
        if status not in (200, 204):
            raise RuntimeError(f"CfKvBackend put failed: HTTP {status}")

    def delete(self, key: str) -> None:
        status, _ = self._http.request("DELETE", self._url(key), None, self._headers())
        if status not in (200, 204, 404):
            raise RuntimeError(f"CfKvBackend delete failed: HTTP {status}")


def backend_from_env() -> CredentialBackend:
    """Select a credential backend from the MCP_STORAGE_BACKEND env var."""
    kind = os.environ.get("MCP_STORAGE_BACKEND", "local").lower()
    if kind in ("local", "local-fs", ""):
        return LocalFsBackend()
    if kind == "cf-kv":
        return CfKvBackend(
            base_url=os.environ["MCP_KV_BASE_URL"],
            token=os.environ.get("MCP_KV_TOKEN"),
        )
    raise ValueError(f"Unknown MCP_STORAGE_BACKEND: {kind}")
