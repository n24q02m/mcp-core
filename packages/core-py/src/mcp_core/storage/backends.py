"""Pluggable credential backends.

A backend stores and retrieves OPAQUE ciphertext blobs keyed by a string.
Encryption and key derivation live in PerPluginStore; backends never see
plaintext. This seam lets MCP servers run serverless (e.g. Cloudflare Workers
KV) while stdio/VM deployments keep the on-disk layout via LocalFsBackend.
"""

from __future__ import annotations
import asyncio
import json

import os
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable
from urllib.parse import quote

import httpx

# Reserved KV key for the readiness probe (E.1). The kv.internal outbound handler
# answers a GET of this key with {"ready": true} only once outbound-interception
# is wired, letting the container gate its first credential PUT on it.
_READY_KEY = "__ready"


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

    "<plugin>/config"                     -> ~/.<plugin>-mcp/config.json
    "<plugin>/subs/<sub>/config"          -> ~/.<plugin>-mcp/subs/<sub>/config.json
    "<plugin>/tokens/<provider>"          -> ~/.<plugin>-mcp/tokens/<provider>.json
    "<plugin>/subs/<sub>/tokens/<prov>"   -> ~/.<plugin>-mcp/subs/<sub>/tokens/<prov>.json
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
    elif rest.startswith("subs/") and "/tokens/" in rest:
        mid = rest[len("subs/") :]
        sub, _, provider = mid.partition("/tokens/")
        _validate_component(sub)
        _validate_component(provider)
        path = base / "subs" / sub / "tokens" / f"{provider}.json"
    elif rest.startswith("tokens/"):
        provider = rest[len("tokens/") :]
        _validate_component(provider)
        path = base / "tokens" / f"{provider}.json"
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


class _HttpxHttp:
    """Minimal HTTP client over httpx, returning (status, body)."""

    def request(self, method: str, url: str, data: Optional[bytes], headers: dict) -> tuple[int, bytes]:
        resp = httpx.request(method, url, content=data, headers=headers, timeout=10.0)
        return (resp.status_code, resp.content)


class CfKvBackend:
    """Stores blobs in a Cloudflare Workers KV namespace over HTTP.

    Error contract: 200 -> data, 404 -> absent (None for get, no-op for delete).
    Every other HTTP status, plus transport errors (httpx connection/timeout
    errors), raises -- failures are loud, never silently returned as data.
    """

    def __init__(self, base_url: str, token: Optional[str] = None, http=None) -> None:
        self._base_url = base_url
        self._token = token
        self._http = http if http is not None else _HttpxHttp()

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

    async def ready(self, retries: int = 8, delay: float = 0.5) -> bool:
        """Poll the KV outbound handler's readiness probe (E.1 race gate).

        On Cloudflare the container's first credential PUT can race
        applyOutboundInterception(); the kv.internal handler answers a GET on the
        reserved ``__ready`` key with ``{"ready": true}`` only once interception
        is wired. Poll up to ``retries`` times (``delay`` seconds apart),
        tolerating transport errors (a not-yet-wired host throws). Returns True
        once ready, False if it never becomes ready within the budget (the caller
        may proceed and rely on the client retry-on-500 backstop).
        """

        url = self._url(_READY_KEY)
        for attempt in range(retries):
            try:
                status, body = self._http.request("GET", url, None, self._headers())
                if status == 200 and json.loads(body or b"{}").get("ready") is True:
                    return True
            except Exception:
                pass  # host not wired yet / transient transport error -> keep polling
            if attempt + 1 < retries:
                await asyncio.sleep(delay)
        return False


def backend_from_env() -> CredentialBackend:
    """Select a credential backend from the MCP_STORAGE_BACKEND env var."""
    kind = os.environ.get("MCP_STORAGE_BACKEND", "local").lower()
    if kind in ("local", "local-fs", ""):
        return LocalFsBackend()
    if kind == "cf-kv":
        base_url = os.environ.get("MCP_KV_BASE_URL")
        if not base_url:
            raise ValueError("MCP_KV_BASE_URL is required when MCP_STORAGE_BACKEND=cf-kv")
        return CfKvBackend(base_url=base_url, token=os.environ.get("MCP_KV_TOKEN"))
    raise ValueError(f"Unknown MCP_STORAGE_BACKEND: {kind}")
