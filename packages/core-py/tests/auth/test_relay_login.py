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

from collections.abc import Iterator

import pytest

from mcp_core.auth.relay_login import (
    _fails,
    _sessions,
    configure_relay_login,
    login_get_handler,
    login_post_handler,
    require_relay_session,
)


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
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


async def test_login_get_uses_shared_form_shell() -> None:
    """The /login form must reuse the relay credential-form shell.

    Visual parity with ``render_credential_form`` is enforced by checking the
    shared CSS classes (``.field-input``, ``.field-label``, ``.field-group``,
    ``.required-badge``, ``.submit-btn``) appear in the rendered HTML, plus
    the dark-theme palette colour ``#0f0f0f`` and the page ``<title>``.
    """
    response = await login_get_handler("/authorize?session=abc")
    body = response.body.decode()
    # Shared shell markers (head + global CSS variables).
    assert "<title>Relay login</title>" in body
    assert "#0f0f0f" in body  # body background from shared CSS
    # Card classes carried over from credential_form.
    assert 'class="container"' in body
    assert 'class="card"' in body
    assert 'class="server-name"' in body
    # Field group structure replaces the bare <input>.
    assert 'class="field-group"' in body
    assert 'class="field-label"' in body
    assert 'class="field-input"' in body
    assert 'class="required-badge" aria-hidden="true"' in body
    assert 'class="submit-btn"' in body
    # Behavioural contract preserved (POST endpoint, hidden next, password input).
    assert 'action="/login"' in body
    assert 'method="POST"' in body
    assert 'name="next" value="/authorize?session=abc"' in body
    assert 'type="password"' in body
    assert 'name="password"' in body


async def test_login_get_escapes_next_param() -> None:
    """``next`` query value flows into the hidden input HTML-escaped."""
    response = await login_get_handler('/authorize?x=<script>alert("xss")</script>')
    body = response.body.decode()
    assert "<script>" not in body
    assert "&lt;script&gt;" in body
    assert "&quot;" in body


async def test_wrong_password_401() -> None:
    configure_relay_login("secret123")
    result = await login_post_handler({"password": "wrong", "next": "/authorize"}, ip="1.1.1.1")
    assert result.status_code == 401
    html = result.body.decode("utf-8")
    assert "Invalid password." in html
    assert 'class="status-box error"' in html
    assert 'role="alert"' in html
    assert 'aria-invalid="true"' in html
    assert 'aria-errormessage="login-error"' in html


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
    html = result.body.decode("utf-8")
    assert "Too many login attempts. Try again later." in html
    assert 'class="status-box error"' in html
    assert 'role="alert"' in html
    assert 'aria-invalid="true"' in html
    assert 'aria-errormessage="login-error"' in html
