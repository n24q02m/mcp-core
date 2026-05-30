"""MCP relay edge auth — password gate for ``/authorize`` (Python parity).

When ``MCP_RELAY_PASSWORD`` is set, the ``/authorize`` route is fronted by a
thin cookie-session check. Unauthenticated requests are redirected to
``/login`` where the user submits the password once, gets a 24h
``mcp_relay_session`` cookie, and continues to ``/authorize``.

Empty / unset password disables the gate entirely (single-user dev mode).

Brute-force protection: 5 wrong submissions per IP within a 15-minute
sliding window block further attempts with HTTP 429 + ``Retry-After``.

Per spec ``2026-05-01-stdio-pure-http-multiuser §4.2.1``. TypeScript parity
lives at ``packages/core-ts/src/auth/relay-login.ts``.
"""

from __future__ import annotations

import html
import hmac
import secrets
import time
from typing import Any
from urllib.parse import quote

from starlette.responses import HTMLResponse, RedirectResponse, Response

from mcp_core.auth.credential_form import render_form_shell

# In-memory session + brute-force stores. Module-scope is intentional: each
# container hosts a single relay app, so a single shared map matches the
# operational model. Test code resets these directly via fixtures.
_sessions: dict[str, float] = {}  # sid -> expires_at_epoch
_fails: dict[str, tuple[int, float]] = {}  # ip -> (count, first_at_epoch)

SESSION_TTL_S = 24 * 60 * 60
FAIL_WINDOW_S = 15 * 60
FAIL_LIMIT = 5

_configured_password = ""


def configure_relay_login(password: str) -> None:
    """Set the password the gate should enforce. Empty string disables."""
    global _configured_password
    _configured_password = password or ""


def _bump_fail(ip: str) -> tuple[bool, int]:
    """Record a failed login attempt; return ``(blocked, retry_after_s)``."""
    now = time.time()
    entry = _fails.get(ip)
    if not entry or now - entry[1] > FAIL_WINDOW_S:
        _fails[ip] = (1, now)
        return False, 0
    count, first_at = entry
    count += 1
    _fails[ip] = (count, first_at)
    if count > FAIL_LIMIT:
        return True, int(FAIL_WINDOW_S - (now - first_at))
    return False, 0


def _clear_fail(ip: str) -> None:
    _fails.pop(ip, None)


def _get_safe_next(input_val: Any) -> str:
    """Validates the ``next`` parameter to prevent Open Redirect vulnerabilities.

    It must start with a single ``/`` and NOT be followed by another ``/``,
    ``\\``, or any whitespace/control character that some browsers might
    normalize into a protocol-relative URL.
    """
    next_ = str(input_val or "/authorize")
    if not next_.startswith("/") or next_.startswith("//") or next_.startswith("/\\") or next_.startswith("\\\\"):
        return "/authorize"
    # Block cases like "/ google.com" or "/\tgoogle.com" (ASCII <= 32).
    if len(next_) > 1 and ord(next_[1]) <= 32:
        return "/authorize"
    return next_


async def require_relay_session(
    cookies: dict[str, str],
    original_url: str,
    password: str | None = None,
) -> RedirectResponse | None:
    """Cookie gate check.

    Returns ``None`` when the request may proceed (gate disabled or cookie
    valid). Otherwise returns a 302 redirect to ``/login?next=<encoded>``.
    """
    pwd = password if password is not None else _configured_password
    if not pwd:
        return None
    sid = cookies.get("mcp_relay_session")
    if sid and _sessions.get(sid, 0) > time.time():
        return None
    next_ = quote(original_url, safe="")
    return RedirectResponse(url=f"/login?next={next_}", status_code=302)


def _render_login_form(next_url: str, error_msg: str | None = None) -> str:
    """Render the password form using the shared relay form shell."""
    safe_next = html.escape(str(next_url))

    aria_invalid = ' aria-invalid="true"' if error_msg else ""
    error_box = f'\n                <div class="status-box error" role="alert" style="display: block; margin-top: 1rem;">{html.escape(error_msg)}</div>' if error_msg else ""

    body_html = f"""    <div class="container">
        <div class="card">
            <div class="server-header">
                <h1 class="server-name">Relay login</h1>
                <div class="server-id">mcp-relay</div>
                <p class="server-description">Enter the relay password shared by your deployer.</p>
            </div>

            <p class="form-title">Authenticate</p>

            <form method="POST" action="/login" novalidate>
                <input type="hidden" name="next" value="{safe_next}">
                <div class="field-group">
                    <label for="field-password" class="field-label">
                        Relay password
                        <span class="required-badge" aria-hidden="true">Required</span>
                    </label>
                    <input
                        id="field-password"
                        type="password"
                        name="password"
                        class="field-input"
                        placeholder="Relay password"
                        autocomplete="current-password"
                        autocorrect="off"
                        autocapitalize="off"
                        spellcheck="false"
                        required
                        autofocus{aria_invalid}
                    />
                </div>

                <button type="submit" class="submit-btn">Continue</button>{error_box}
            </form>
        </div>
    </div>"""
    return render_form_shell("Relay login", body_html)

async def login_get_handler(next: str = "/authorize") -> HTMLResponse:
    """Render the password form using the shared relay form shell.

    The visible card mirrors the relay credential form: dark theme, Inter
    fall-back font stack, ``.field-group`` / ``.field-label`` / ``.field-input``
    classes for the password input, and a primary submit button matching the
    "Connect" styling. The form keeps a plain HTML POST (no JavaScript) so the
    gate works even with a strict CSP that blocks inline scripts.
    """
    next_url = _get_safe_next(next)
    return HTMLResponse(_render_login_form(next_url))


async def login_post_handler(form: dict, ip: str) -> Response:
    """Verify the password and (on success) issue a session cookie."""
    now = time.time()
    next_ = _get_safe_next(form.get("next"))
    fail = _fails.get(ip)

    if fail and now - fail[1] < FAIL_WINDOW_S and fail[0] >= FAIL_LIMIT:
        retry_after = int(FAIL_WINDOW_S - (now - fail[1]))
        return HTMLResponse(
            content=_render_login_form(next_, "Too many login attempts. Try again later."),
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    password = str(form.get("password", ""))
    if not _configured_password or not hmac.compare_digest(password.encode(), _configured_password.encode()):
        _bump_fail(ip)
        return HTMLResponse(
            content=_render_login_form(next_, "Invalid password."),
            status_code=401,
        )
    _clear_fail(ip)
    sid = secrets.token_hex(32)
    _sessions[sid] = time.time() + SESSION_TTL_S
    cookie = f"mcp_relay_session={sid}; HttpOnly; Secure; SameSite=Lax; Max-Age={SESSION_TTL_S}; Path=/"
    return RedirectResponse(url=next_, status_code=302, headers={"set-cookie": cookie})
