"""Tests for the relay password gate wired into the delegated OAuth app.

Mirrors the gate semantics PR #158 added to ``create_local_oauth_app``: when
``MCP_RELAY_PASSWORD`` is set, ``/authorize`` is fronted by a cookie-session
middleware that redirects unauthenticated requests to ``/login``. ``/token``,
``/register``, ``/setup-status``, ``/callback``, ``/.well-known/*`` stay
ungated by design — they are machine endpoints or mid-OAuth callbacks.

Tests use Starlette's ``TestClient`` and ``follow_redirects=False`` so we can
observe the 302 the gate emits without losing the Location header.
"""

from __future__ import annotations

from collections.abc import Iterator
from urllib.parse import urlparse

import pytest
from starlette.testclient import TestClient

from mcp_core.auth.delegated_oauth_app import (
    UpstreamOAuthConfig,
    create_delegated_oauth_app,
)
from mcp_core.auth.relay_login import _fails, _sessions


@pytest.fixture(autouse=True)
def _reset_relay_state() -> Iterator[None]:
    """Clear module-scoped sessions + brute-force counters between cases."""
    _sessions.clear()
    _fails.clear()
    yield
    _sessions.clear()
    _fails.clear()


def _make_app(monkeypatch: pytest.MonkeyPatch, password: str):
    monkeypatch.setenv("MCP_RELAY_PASSWORD", password)
    cfg = UpstreamOAuthConfig(
        token_url="https://upstream.example/token",
        client_id="upstream-client",
        client_secret="upstream-secret",
        scopes=["read"],
        authorize_url="https://upstream.example/authorize",
    )
    app, _ = create_delegated_oauth_app(
        server_name="test-delegated-relay",
        flow="redirect",
        upstream=cfg,
        on_token_received=lambda tokens: "sub-test",
    )
    return app


def _authorize_qs() -> dict[str, str]:
    return {
        "client_id": "local-browser",
        "redirect_uri": "http://127.0.0.1:5555/callback",
        "state": "state-xyz",
        "code_challenge": "a" * 43,
        "code_challenge_method": "S256",
    }


def test_authorize_without_cookie_redirects_to_login(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the gate is enabled, GET /authorize without cookie -> 302 /login."""
    app = _make_app(monkeypatch, "secret123")
    client = TestClient(app, base_url="http://localhost")
    resp = client.get("/authorize", params=_authorize_qs(), follow_redirects=False)
    assert resp.status_code == 302
    loc = resp.headers["location"]
    assert loc.startswith("/login?next=")
    # Original /authorize URL should be encoded into ?next=
    from urllib.parse import unquote

    assert "/authorize" in unquote(loc)


def test_authorize_with_valid_cookie_passes_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """With a valid mcp_relay_session cookie, /authorize reaches upstream."""
    import re

    app = _make_app(monkeypatch, "secret123")
    # ``base_url=https://localhost`` so the ``Secure`` cookie that the gate
    # issues is accepted on the subsequent request. Without HTTPS the
    # TestClient strips Secure cookies before resending them and the
    # follow-up /authorize request appears to come without a cookie,
    # incorrectly tripping the gate.
    client = TestClient(app, base_url="https://localhost")

    # Mint cookie via POST /login.
    login_resp = client.post(
        "/login",
        data={"password": "secret123", "next": "/authorize"},
        follow_redirects=False,
    )
    assert login_resp.status_code == 302
    set_cookie = login_resp.headers.get("set-cookie", "")
    assert "mcp_relay_session=" in set_cookie

    # Extract sid manually so we can attach it explicitly as a Cookie header
    # (avoids relying on TestClient cookie-jar Secure handling).
    match = re.search(r"mcp_relay_session=([a-f0-9]{64})", set_cookie)
    assert match is not None
    sid = match.group(1)

    # Hit /authorize with the cookie. Inner handler should run and emit a
    # 302 to the upstream authorize URL, NOT /login.
    resp = client.get(
        "/authorize",
        params=_authorize_qs(),
        headers={"Cookie": f"mcp_relay_session={sid}"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    loc = resp.headers["location"]
    assert not loc.startswith("/login")
    assert "upstream.example/authorize" in loc
    # The upstream URL should preserve the configured scopes and a state token.
    parsed = urlparse(loc)
    assert parsed.netloc.endswith("upstream.example")


def test_authorize_with_empty_password_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty MCP_RELAY_PASSWORD disables the gate (single-user dev mode)."""
    app = _make_app(monkeypatch, "")
    client = TestClient(app, base_url="http://localhost")
    resp = client.get("/authorize", params=_authorize_qs(), follow_redirects=False)
    assert resp.status_code == 302
    loc = resp.headers["location"]
    assert not loc.startswith("/login")
    assert "upstream.example/authorize" in loc


def test_login_get_renders_form(monkeypatch: pytest.MonkeyPatch) -> None:
    """GET /login renders the password form HTML."""
    app = _make_app(monkeypatch, "secret123")
    client = TestClient(app, base_url="http://localhost")
    resp = client.get("/login")
    assert resp.status_code == 200
    body = resp.text
    assert "Relay login" in body
    assert 'name="password"' in body


def test_login_post_wrong_password_returns_401(monkeypatch: pytest.MonkeyPatch) -> None:
    """POST /login with the wrong password -> 401, no cookie issued."""
    app = _make_app(monkeypatch, "secret123")
    client = TestClient(app, base_url="http://localhost")
    resp = client.post(
        "/login",
        data={"password": "wrong", "next": "/authorize"},
        follow_redirects=False,
    )
    assert resp.status_code == 401
    assert "mcp_relay_session=" not in resp.headers.get("set-cookie", "")


def test_machine_endpoints_not_gated(monkeypatch: pytest.MonkeyPatch) -> None:
    """/token, /register, /setup-status, /.well-known/* must stay ungated.

    These are machine endpoints (DCR / token exchange / metadata polling) and
    /callback is hit by the upstream provider mid-OAuth — gating any of them
    would break the protocol.
    """
    app = _make_app(monkeypatch, "secret123")
    client = TestClient(app, base_url="http://localhost")

    # /token: missing body -> 400, not redirect.
    tok_resp = client.post("/token", follow_redirects=False)
    assert tok_resp.status_code != 302
    assert tok_resp.status_code >= 400

    # /register: 201 with echoed body.
    reg_resp = client.post("/register", json={}, follow_redirects=False)
    assert reg_resp.status_code == 201

    # /setup-status: 200 JSON.
    stat_resp = client.get("/setup-status", follow_redirects=False)
    assert stat_resp.status_code == 200

    # /.well-known/oauth-authorization-server: 200.
    well_resp = client.get(
        "/.well-known/oauth-authorization-server",
        follow_redirects=False,
    )
    assert well_resp.status_code == 200
