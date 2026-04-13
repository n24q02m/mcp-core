"""Tests for the delegated OAuth Starlette app (device_code + redirect flows).

Stubs the upstream endpoints via ``httpx.MockTransport`` so the flow runs
entirely in-memory without opening real sockets.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from starlette.testclient import TestClient

from mcp_core.auth import delegated_oauth_app as delegated_mod
from mcp_core.auth.delegated_oauth_app import (
    UpstreamOAuthConfig,
    create_delegated_oauth_app,
)


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class _StubUpstream:
    """Swap ``httpx.AsyncClient`` with a mock-transport backed client.

    ``handler`` receives the intercepted request and returns an ``httpx.Response``.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch, handler):
        self._handler = handler
        self._real_async_client = httpx.AsyncClient

        def fake_factory(*_args: Any, **_kwargs: Any) -> httpx.AsyncClient:
            transport = httpx.MockTransport(handler)
            return self._real_async_client(transport=transport)

        monkeypatch.setattr(delegated_mod.httpx, "AsyncClient", fake_factory)


# ---------------------------------------------------------------------------
# Redirect flow
# ---------------------------------------------------------------------------


def test_redirect_authorize_redirects_to_upstream(monkeypatch):
    """GET /authorize redirects to upstream.authorize_url with state + redirect_uri."""
    cfg = UpstreamOAuthConfig(
        token_url="https://example.test/token",
        client_id="upstream-client",
        scopes=["read", "write"],
        authorize_url="https://example.test/authorize",
    )
    app, _ = create_delegated_oauth_app(
        server_name="test",
        flow="redirect",
        upstream=cfg,
        on_token_received=lambda tokens: None,
    )
    client = TestClient(app, base_url="http://localhost")
    verifier, challenge = _pkce_pair()
    resp = client.get(
        "/authorize",
        params={
            "client_id": "mcp-client",
            "redirect_uri": "http://localhost/cb",
            "state": "client-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert resp.status_code in (302, 307)
    loc = resp.headers["location"]
    assert loc.startswith("https://example.test/authorize")
    parsed = urlparse(loc)
    qs = parse_qs(parsed.query)
    assert qs["client_id"] == ["upstream-client"]
    assert qs["redirect_uri"] == ["http://localhost/callback"]
    assert qs["response_type"] == ["code"]
    assert qs["scope"] == ["read write"]
    assert qs["state"][0]  # nonce present; value is ours


def test_redirect_callback_exchanges_code_and_calls_on_token_received(monkeypatch):
    received: list[dict[str, Any]] = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://example.test/token"
        form = dict(httpx.QueryParams(request.content.decode()))
        assert form["grant_type"] == "authorization_code"
        assert form["code"] == "upstream-auth-code"
        assert form["client_id"] == "upstream-client"
        assert form["client_secret"] == "shh"
        assert form["redirect_uri"] == "http://localhost/callback"
        return httpx.Response(
            200,
            json={
                "access_token": "up-access",
                "refresh_token": "up-refresh",
                "expires_in": 3600,
            },
        )

    _StubUpstream(monkeypatch, upstream_handler)

    cfg = UpstreamOAuthConfig(
        token_url="https://example.test/token",
        client_id="upstream-client",
        client_secret="shh",
        scopes=["read"],
        authorize_url="https://example.test/authorize",
    )

    def on_token(tokens: dict[str, Any]) -> None:
        received.append(tokens)

    app, issuer = create_delegated_oauth_app(
        server_name="test",
        flow="redirect",
        upstream=cfg,
        on_token_received=on_token,
    )
    client = TestClient(app, base_url="http://localhost")

    verifier, challenge = _pkce_pair()
    resp = client.get(
        "/authorize",
        params={
            "client_id": "mcp-client",
            "redirect_uri": "http://localhost/cb",
            "state": "client-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    nonce = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]

    cb = client.get(
        "/callback",
        params={"code": "upstream-auth-code", "state": nonce},
        follow_redirects=False,
    )
    assert cb.status_code in (302, 307)
    assert received == [{"access_token": "up-access", "refresh_token": "up-refresh", "expires_in": 3600}]

    final_loc = cb.headers["location"]
    assert final_loc.startswith("http://localhost/cb?")
    qs = parse_qs(urlparse(final_loc).query)
    assert qs["state"] == ["client-state"]
    auth_code = qs["code"][0]

    tok = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "code_verifier": verifier,
        },
    )
    assert tok.status_code == 200
    token_body = tok.json()
    assert token_body["token_type"] == "Bearer"
    claims = issuer.verify_access_token(token_body["access_token"])
    assert claims["sub"] == "local-user"


def test_redirect_callback_rejects_invalid_state():
    cfg = UpstreamOAuthConfig(
        token_url="https://example.test/token",
        client_id="upstream-client",
        authorize_url="https://example.test/authorize",
    )
    app, _ = create_delegated_oauth_app(
        server_name="test",
        flow="redirect",
        upstream=cfg,
        on_token_received=lambda t: None,
    )
    client = TestClient(app, base_url="http://localhost")
    resp = client.get(
        "/callback",
        params={"code": "x", "state": "unknown-nonce"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


# ---------------------------------------------------------------------------
# Device code flow
# ---------------------------------------------------------------------------


def _device_cfg() -> UpstreamOAuthConfig:
    return UpstreamOAuthConfig(
        token_url="https://example.test/token",
        client_id="upstream-client",
        scopes=["drive"],
        device_auth_url="https://example.test/device",
    )


def test_device_code_authorize_renders_user_code_page(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/device"):
            return httpx.Response(
                200,
                json={
                    "device_code": "dc-abc",
                    "user_code": "WXYZ-1234",
                    "verification_url": "https://example.test/verify",
                    "interval": 5,
                    "expires_in": 600,
                },
            )
        # Polling: never grant in this test; slow interval keeps us from looping.
        return httpx.Response(400, json={"error": "authorization_pending"})

    _StubUpstream(monkeypatch, handler)

    app, _ = create_delegated_oauth_app(
        server_name="gdrive",
        flow="device_code",
        upstream=_device_cfg(),
        on_token_received=lambda t: None,
    )
    client = TestClient(app, base_url="http://localhost")
    verifier, challenge = _pkce_pair()
    resp = client.get(
        "/authorize",
        params={
            "client_id": "mcp-client",
            "redirect_uri": "http://localhost/cb",
            "state": "client-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "WXYZ-1234" in resp.text
    assert "https://example.test/verify" in resp.text


def test_device_code_background_poll_on_token_received(monkeypatch):
    received: list[dict[str, Any]] = []
    call = {"poll": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = str(request.url)
        if path.endswith("/device"):
            return httpx.Response(
                200,
                json={
                    "device_code": "dc-abc",
                    "user_code": "WXYZ-1234",
                    "verification_url": "https://example.test/verify",
                    "interval": 0,
                    "expires_in": 600,
                },
            )
        # /token poll: grant on first call.
        call["poll"] += 1
        return httpx.Response(
            200,
            json={"access_token": "up-access", "refresh_token": "up-refresh"},
        )

    _StubUpstream(monkeypatch, handler)

    # Make polling sleep almost nothing.
    orig_sleep = asyncio.sleep

    async def quick_sleep(_s: float) -> None:
        await orig_sleep(0)

    monkeypatch.setattr(delegated_mod.asyncio, "sleep", quick_sleep)

    app, _ = create_delegated_oauth_app(
        server_name="gdrive",
        flow="device_code",
        upstream=_device_cfg(),
        on_token_received=lambda t: received.append(t),
    )

    with TestClient(app, base_url="http://localhost") as client:
        _verifier, challenge = _pkce_pair()
        resp = client.get(
            "/authorize",
            params={
                "client_id": "mcp-client",
                "redirect_uri": "http://localhost/cb",
                "state": "client-state",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert resp.status_code == 200

        # Poll setup-status until complete (deterministic because sleep==0).
        import time

        deadline = time.time() + 5
        status = ""
        while time.time() < deadline:
            status = client.get("/setup-status").json().get("gdrive")
            if status == "complete":
                break
            time.sleep(0.01)
        assert status == "complete"
        assert received == [{"access_token": "up-access", "refresh_token": "up-refresh"}]


def test_device_code_authorization_pending_continues_polling(monkeypatch):
    received: list[dict[str, Any]] = []
    state = {"poll": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = str(request.url)
        if path.endswith("/device"):
            return httpx.Response(
                200,
                json={
                    "device_code": "dc-abc",
                    "user_code": "PEND-0000",
                    "verification_url": "https://example.test/verify",
                    "interval": 0,
                    "expires_in": 600,
                },
            )
        state["poll"] += 1
        if state["poll"] < 3:
            return httpx.Response(400, json={"error": "authorization_pending"})
        return httpx.Response(200, json={"access_token": "finally"})

    _StubUpstream(monkeypatch, handler)

    orig_sleep = asyncio.sleep

    async def quick_sleep(_s: float) -> None:
        await orig_sleep(0)

    monkeypatch.setattr(delegated_mod.asyncio, "sleep", quick_sleep)

    app, _ = create_delegated_oauth_app(
        server_name="gdrive",
        flow="device_code",
        upstream=_device_cfg(),
        on_token_received=lambda t: received.append(t),
    )

    with TestClient(app, base_url="http://localhost") as client:
        _verifier, challenge = _pkce_pair()
        client.get(
            "/authorize",
            params={
                "client_id": "mcp-client",
                "redirect_uri": "http://localhost/cb",
                "state": "client-state",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        import time

        deadline = time.time() + 5
        status = ""
        while time.time() < deadline:
            status = client.get("/setup-status").json().get("gdrive")
            if status == "complete":
                break
            time.sleep(0.01)
        assert status == "complete"
        assert state["poll"] >= 3
        assert received == [{"access_token": "finally"}]


def test_invalid_flow_config_raises():
    with pytest.raises(ValueError, match="authorize_url"):
        create_delegated_oauth_app(
            server_name="test",
            flow="redirect",
            upstream=UpstreamOAuthConfig(token_url="https://example.test/token", client_id="x"),
            on_token_received=lambda t: None,
        )
    with pytest.raises(ValueError, match="device_auth_url"):
        create_delegated_oauth_app(
            server_name="test",
            flow="device_code",
            upstream=UpstreamOAuthConfig(token_url="https://example.test/token", client_id="x"),
            on_token_received=lambda t: None,
        )
