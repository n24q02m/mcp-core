"""Tests for the MCP relay password gate (Python parity).

The gate is a thin cookie-session ticker that fronts ``/authorize`` when
``MCP_RELAY_PASSWORD`` is set. Empty / unset password disables the gate;
five wrong submissions per IP within 15 minutes block further attempts
with HTTP 429.

Mirrors ``packages/core-ts/tests/auth/relay-login.test.ts``. Tests use the
plain dict / object shapes the handlers expect so we don't depend on a
live Starlette test client; integration is covered separately by
``test_local_oauth_app.py``.
"""

from __future__ import annotations

import pytest

from mcp_core.auth.relay_login import (
    _fails,
    _sessions,
    configure_relay_login,
    login_post_handler,
    require_relay_session,
)


@pytest.fixture(autouse=True)
def _reset() -> None:
    """Clear module-scoped sessions + brute-force counters between cases."""
    _sessions.clear()
    _fails.clear()
    yield
    _sessions.clear()
    _fails.clear()


async def test_empty_env_disables_gate() -> None:
    configure_relay_login("")
    cookies: dict[str, str] = {}
    # require_relay_session returns ``None`` when the password is empty,
    # signalling the caller that the gate is disabled and the request
    # should pass through.
    assert await require_relay_session(cookies, "/authorize", password="") is None


async def test_wrong_password_401() -> None:
    configure_relay_login("secret123")
    result = await login_post_handler({"password": "wrong", "next": "/authorize"}, ip="1.1.1.1")
    assert result.status_code == 401


async def test_correct_password_sets_cookie_and_redirects() -> None:
    configure_relay_login("secret123")
    result = await login_post_handler({"password": "secret123", "next": "/authorize"}, ip="2.2.2.2")
    assert result.status_code == 302
    set_cookie = result.headers.get("set-cookie", "")
    assert "mcp_relay_session=" in set_cookie


async def test_brute_force_6th_attempt_429() -> None:
    configure_relay_login("secret123")
    for _ in range(5):
        await login_post_handler({"password": "wrong", "next": "/"}, ip="3.3.3.3")
    result = await login_post_handler({"password": "wrong", "next": "/"}, ip="3.3.3.3")
    assert result.status_code == 429
    assert "retry-after" in {k.lower() for k in result.headers.keys()}
