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

import hmac
import secrets
import time
from urllib.parse import quote

from starlette.responses import HTMLResponse, RedirectResponse, Response

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


async def login_get_handler(next: str = "/authorize") -> HTMLResponse:
    """Render the password form."""
    safe_next = next.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    body = f"""<!DOCTYPE html><html><body><h1>Relay login</h1>
<form method="POST" action="/login">
<input type="hidden" name="next" value="{safe_next}">
<input type="password" name="password" placeholder="Relay password" required autofocus>
<button type="submit">Continue</button>
</form></body></html>"""
    return HTMLResponse(body)


async def login_post_handler(form: dict, ip: str) -> Response:
    """Verify the password and (on success) issue a session cookie."""
    now = time.time()
    fail = _fails.get(ip)
    if fail and now - fail[1] < FAIL_WINDOW_S and fail[0] >= FAIL_LIMIT:
        retry_after = int(FAIL_WINDOW_S - (now - fail[1]))
        return Response(
            "Too many login attempts. Try again later.",
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )
    password = str(form.get("password", ""))
    next_ = str(form.get("next", "/authorize"))
    if not _configured_password or not hmac.compare_digest(password.encode(), _configured_password.encode()):
        _bump_fail(ip)
        return Response("Invalid password.", status_code=401)
    _clear_fail(ip)
    sid = secrets.token_hex(32)
    _sessions[sid] = time.time() + SESSION_TTL_S
    cookie = f"mcp_relay_session={sid}; HttpOnly; Secure; SameSite=Lax; Max-Age={SESSION_TTL_S}; Path=/"
    return RedirectResponse(url=next_, status_code=302, headers={"set-cookie": cookie})
