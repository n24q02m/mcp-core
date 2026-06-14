"""Tests for mcp_core.http SSRF guard."""

import socket

import httpcore
import httpx
import pytest

from mcp_core.http import (
    SSRFBlockedError,
    get_ssrf_safe_sync_client,
    validate_url_and_get_ip,
    vet_api_base,
)
from mcp_core.http.ssrf import (
    AsyncSSRFSafeBackend,
    SyncSSRFSafeBackend,
    SyncSSRFSafeTransport,
)


def _fake_getaddrinfo(ip: str):
    def fake(host, port, *args, **kwargs):
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (ip, port or 443))]

    return fake


# --- validate_url_and_get_ip: scheme + hostname ---


def test_rejects_non_http_scheme():
    with pytest.raises(SSRFBlockedError, match="scheme"):
        validate_url_and_get_ip("ftp://example.com/x")


def test_rejects_missing_hostname():
    with pytest.raises(SSRFBlockedError, match="hostname"):
        validate_url_and_get_ip("http://")


# --- IP policy (DNS mocked, no network) ---


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",  # RFC1918
        "192.168.1.1",  # RFC1918
        "100.64.0.1",  # CGNAT
        "169.254.169.254",  # link-local (cloud metadata)
        "0.0.0.0",
        "224.0.0.1",  # multicast
        "::ffff:10.0.0.1",  # IPv4-mapped IPv6
    ],
)
def test_blocks_private_ips_by_default(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(ip))
    with pytest.raises(SSRFBlockedError):
        validate_url_and_get_ip("https://evil.example.com/")


def test_blocks_loopback_by_default(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    with pytest.raises(SSRFBlockedError):
        validate_url_and_get_ip("https://evil.example.com/")


def test_allow_loopback_flag(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    ip = validate_url_and_get_ip("http://localhost:11434", allow_loopback=True)
    assert ip == "127.0.0.1"


def test_allow_private_flag(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("10.1.2.3"))
    ip = validate_url_and_get_ip("http://gateway.lan:4000", allow_private=True)
    assert ip == "10.1.2.3"


def test_allows_public_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    assert validate_url_and_get_ip("https://example.com/") == "93.184.216.34"


@pytest.mark.parametrize("ip", ["0.0.0.0", "::", "::ffff:0.0.0.0"])
def test_blocks_unspecified_even_with_allow_private(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(ip))
    with pytest.raises(SSRFBlockedError, match="[Uu]nspecified"):
        validate_url_and_get_ip("https://evil.example.com/", allow_private=True, allow_loopback=True)


# --- AsyncSSRFSafeBackend ---


async def test_connect_unix_socket_rejected():
    backend = AsyncSSRFSafeBackend()
    with pytest.raises(SSRFBlockedError):
        await backend.connect_unix_socket("/tmp/x.sock")


# --- SyncSSRFSafeBackend (sync sibling: resolve+vet ONCE, dial the IP literal) ---


def test_sync_connect_unix_socket_rejected():
    backend = SyncSSRFSafeBackend()
    with pytest.raises(SSRFBlockedError):
        backend.connect_unix_socket("/tmp/x.sock")


def test_sync_backend_dials_vetted_ip(monkeypatch):
    """The dialled target must be the resolved IP literal, never the hostname.

    This is the anti-TOCTOU guarantee: the default httpcore.SyncBackend would
    re-resolve at dial time (a DNS-rebinding hole); this backend resolves+vets
    once and passes that IP straight through to the inner backend.
    """
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    dialled: dict = {}

    def fake_connect(self, host, port, **kwargs):
        dialled["host"] = host
        dialled["port"] = port
        return object()  # opaque stream; the test never reads it

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", fake_connect)
    backend = SyncSSRFSafeBackend()
    backend.connect_tcp("example.com", 443)
    assert dialled["host"] == "93.184.216.34"
    assert dialled["port"] == 443


def test_sync_backend_blocks_private_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("10.0.0.1"))
    backend = SyncSSRFSafeBackend()
    with pytest.raises(SSRFBlockedError):
        backend.connect_tcp("evil.example.com", 443)


# --- SyncSSRFSafeTransport ---


def test_sync_transport_rejects_unsupported_scheme():
    transport = SyncSSRFSafeTransport()
    request = httpx.Request("GET", "ftp://example.com/x")
    with pytest.raises(SSRFBlockedError, match="Unsupported scheme"):
        transport.handle_request(request)


def test_sync_transport_preserves_host_and_sni(monkeypatch):
    """Transport pins the IP at the backend but keeps Host + SNI = hostname."""
    captured: dict = {}

    def fake_super_handle(self, request):
        captured["host_header"] = request.headers.get("Host")
        captured["sni"] = request.extensions.get("sni_hostname")
        return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", fake_super_handle)
    transport = SyncSSRFSafeTransport()
    resp = transport.handle_request(httpx.Request("GET", "https://example.com/v1beta1/x"))
    assert resp.status_code == 200
    assert captured["host_header"] == "example.com"
    assert captured["sni"] == "example.com"


def test_get_ssrf_safe_sync_client_uses_sync_transport():
    client = get_ssrf_safe_sync_client()
    assert isinstance(client, httpx.Client)
    assert isinstance(client._transport, SyncSSRFSafeTransport)


# --- vet_api_base policy theo mode (spec D4) ---


def test_vet_api_base_single_user_allows_loopback(monkeypatch):
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    assert vet_api_base("http://localhost:11434") == "http://localhost:11434"


def test_vet_api_base_single_user_blocks_private_without_escape(monkeypatch):
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    monkeypatch.delenv("LLM_API_BASE_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("10.1.2.3"))
    with pytest.raises(SSRFBlockedError):
        vet_api_base("http://gateway.lan:4000")


def test_vet_api_base_single_user_private_escape(monkeypatch):
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    monkeypatch.setenv("LLM_API_BASE_ALLOW_PRIVATE", "1")
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("10.1.2.3"))
    assert vet_api_base("http://gateway.lan:4000") == "http://gateway.lan:4000"


def test_vet_api_base_multi_user_blocks_loopback_and_ignores_escape(monkeypatch):
    monkeypatch.setenv("PUBLIC_URL", "https://wet.example.com")
    monkeypatch.setenv("LLM_API_BASE_ALLOW_PRIVATE", "1")
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    with pytest.raises(SSRFBlockedError):
        vet_api_base("http://localhost:11434")
