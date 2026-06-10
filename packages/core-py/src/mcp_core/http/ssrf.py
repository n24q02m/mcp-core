"""SSRF-safe URL validation + httpx transport (DNS-pinned).

Ported from imagine-mcp ``media.py`` (transport-level pinning — the network
backend dials the already-vetted IP, preserving Host header + SNI). No global
``socket.getaddrinfo`` monkey-patching: this module must be safe to import
from a core library consumed by every MCP server.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import os
import socket
import typing
from urllib.parse import urlparse

import httpcore
import httpx

_DNS_RESOLVER_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="mcp_core_dns")
_SAFE_URL_SCHEMES = frozenset({"http", "https"})
_RESOLVE_TIMEOUT_S = 2.0


class SSRFBlockedError(ValueError):
    """Raised when a URL fails SSRF validation."""


def _vet_ip(ip_str: str, *, allow_private: bool, allow_loopback: bool) -> None:
    ip_obj = ipaddress.ip_address(ip_str)
    if ip_obj.version == 6 and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped
    if ip_obj.is_loopback:
        if not allow_loopback:
            raise SSRFBlockedError(f"URL resolves to loopback address {ip_obj}")
        return
    if not ip_obj.is_global or ip_obj.is_multicast:
        if not allow_private:
            raise SSRFBlockedError(f"URL resolves to internal/private address {ip_obj}")


def _validate_hostname_and_get_ip(
    hostname: str,
    port: int | None,
    *,
    allow_private: bool = False,
    allow_loopback: bool = False,
) -> str:
    try:
        future = _DNS_RESOLVER_POOL.submit(socket.getaddrinfo, hostname, port, socket.AF_UNSPEC)
        addr_info = future.result(timeout=_RESOLVE_TIMEOUT_S)
    except concurrent.futures.TimeoutError as e:
        raise SSRFBlockedError(f"DNS resolution timed out for {hostname!r}") from e
    except socket.gaierror as e:
        raise SSRFBlockedError(f"Could not resolve hostname {hostname!r}") from e

    first_ip: str | None = None
    for res in addr_info:
        ip_str = str(res[4][0])
        # Every resolved IP must pass policy (multi-A-record bypass guard).
        _vet_ip(ip_str, allow_private=allow_private, allow_loopback=allow_loopback)
        if first_ip is None:
            first_ip = ip_str
    if first_ip is None:
        raise SSRFBlockedError(f"No IP found for {hostname!r}")
    return first_ip


def validate_url_and_get_ip(url: str, *, allow_private: bool = False, allow_loopback: bool = False) -> str:
    """Verify URL scheme + resolve hostname; return the first vetted IP."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in _SAFE_URL_SCHEMES:
        raise SSRFBlockedError(f"Unsupported scheme {scheme!r} (http/https only)")
    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("URL is missing hostname")
    return _validate_hostname_and_get_ip(
        hostname,
        parsed.port,
        allow_private=allow_private,
        allow_loopback=allow_loopback,
    )


class AsyncSSRFSafeBackend(httpcore.AsyncNetworkBackend):
    """DNS-pinning backend: dial the vetted IP, never re-resolve (anti-TOCTOU)."""

    def __init__(self, *, allow_private: bool = False, allow_loopback: bool = False) -> None:
        self._backend = httpcore.AnyIOBackend()
        self._allow_private = allow_private
        self._allow_loopback = allow_loopback

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        ip = await asyncio.to_thread(
            _validate_hostname_and_get_ip,
            host,
            port,
            allow_private=self._allow_private,
            allow_loopback=self._allow_loopback,
        )
        return await self._backend.connect_tcp(
            host=ip,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise SSRFBlockedError("Unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        return await self._backend.sleep(seconds)


class AsyncSSRFSafeTransport(httpx.AsyncHTTPTransport):
    """httpx transport with DNS pinning; preserves Host header + SNI."""

    def __init__(
        self,
        *,
        allow_private: bool = False,
        allow_loopback: bool = False,
        **kwargs: typing.Any,
    ) -> None:
        super().__init__(**kwargs)
        self._pool._network_backend = AsyncSSRFSafeBackend(  # ty: ignore[invalid-assignment]
            allow_private=allow_private, allow_loopback=allow_loopback
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.scheme.lower() not in _SAFE_URL_SCHEMES:
            raise SSRFBlockedError(f"Unsupported scheme {url.scheme!r}")
        if "Host" not in request.headers:
            request.headers["Host"] = url.host
        request.extensions["sni_hostname"] = url.host
        return await super().handle_async_request(request)


def get_ssrf_safe_async_client(*, allow_private: bool = False, allow_loopback: bool = False) -> httpx.AsyncClient:
    """New httpx.AsyncClient with SSRF-safe transport (caller owns lifecycle)."""
    return httpx.AsyncClient(
        transport=AsyncSSRFSafeTransport(allow_private=allow_private, allow_loopback=allow_loopback)
    )


def is_multi_user_mode() -> bool:
    """Multi-user remote deployment when PUBLIC_URL is set (spec D4)."""
    return bool(os.environ.get("PUBLIC_URL"))


def vet_api_base(url: str) -> str:
    """Vet a user-supplied LLM api_base per the mode policy (spec D4).

    Single-user/stdio: loopback allowed (self-hosted Ollama on the user's own
    machine); other private ranges need LLM_API_BASE_ALLOW_PRIVATE=1.
    Multi-user (PUBLIC_URL set): loopback + private blocked unconditionally —
    the escape env is deliberately ignored on shared deployments.
    """
    if is_multi_user_mode():
        validate_url_and_get_ip(url, allow_private=False, allow_loopback=False)
    else:
        allow_private = os.environ.get("LLM_API_BASE_ALLOW_PRIVATE") == "1"
        validate_url_and_get_ip(url, allow_private=allow_private, allow_loopback=True)
    return url
