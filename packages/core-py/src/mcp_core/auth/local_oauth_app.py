"""Local OAuth 2.1 Authorization Server as a Starlette ASGI app.

Provides a self-hosted Authorization Server for single-user MCP servers.
Implements the OAuth 2.1 PKCE flow with credential collection via a
browser-rendered form.

Routes:
- GET  /                                        -- Auto-bootstrap PKCE then redirect to /authorize
- GET  /authorize                               -- Render credential form
- POST /authorize                               -- Save credentials, return auth code
- POST /otp                                     -- Submit multi-step credential (OTP / 2FA password)
- POST /token                                   -- Exchange auth code + PKCE verifier for JWT
- GET  /setup-status                            -- Poll background setup completion
- GET  /callback-done                           -- Friendly "tab can be closed" page after PKCE callback
- GET  /.well-known/oauth-authorization-server   -- RFC 8414 metadata
- GET  /.well-known/oauth-protected-resource     -- RFC 9728 metadata

The /mcp endpoint is NOT included -- it is mounted by the transport layer.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import os
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import Any, Union, cast

from loguru import logger
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from mcp_core.auth.credential_form import render_credential_form
from mcp_core.auth.well_known import (
    authorization_server_metadata,
    protected_resource_metadata,
)
from mcp_core.oauth.jwt_issuer import JWTIssuer

# Auth codes and PKCE sessions expire after 10 minutes
_AUTH_CODE_TTL_S = 600
_SESSION_TTL_S = 600

# Multi-step auth (OTP / 2FA password) constraints.
# _OTP_TIMEOUT_S: khoảng thời gian tối đa giữa lúc submit credentials và
# lúc user nhập OTP/password. _OTP_MAX_ATTEMPTS: số lần submit sai tối đa
# trước khi reset pending step session.
_OTP_TIMEOUT_S = 300
_OTP_MAX_ATTEMPTS = 5

# Callback types -- may be sync or async. When async, the handler awaits the
# returned coroutine. This lets telegram-style servers perform async backend
# operations (Telethon connect, send_code, sign_in) without resorting to
# loop.run_until_complete() on a running event loop.
#
# ``on_credentials_saved`` receives the submitted credentials AND a
# per-authorize-session ``SubjectContext`` (``{"sub": "<uuid>"}``). The sub is
# generated fresh when GET /authorize renders the form, threaded through POST
# /authorize, and stamped onto the JWT issued at /token — so consumers that
# persist credentials keyed by ``sub`` (remote-relay multi-user mode) can
# later look them up via AsyncLocalStorage in the Bearer auth scope. Without
# this primitive every browser session collapsed to a static ``local-user``
# subject and leaked credentials across users.
SubjectContext = dict[str, str]
CredentialsCallback = Callable[
    [dict[str, str], SubjectContext], Union[dict[str, Any] | None, Awaitable[dict[str, Any] | None]]
]
# ``on_step_submitted`` also receives the ``SubjectContext`` carried through
# from the original POST /authorize that opened the multi-step flow. /otp
# clients have no sub in their body, so this primitive is the only way for
# telegram-style servers to route OTP / 2FA input to the correct per-user
# Telethon client when serving multi-tenant remote-relay.
StepCallback = Callable[
    [dict[str, str], SubjectContext], Union[dict[str, Any] | None, Awaitable[dict[str, Any] | None]]
]


def _s256_verify(code_verifier: str, code_challenge: str) -> bool:
    """Verify PKCE S256: base64url(sha256(code_verifier)) == code_challenge."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, code_challenge)


def create_local_oauth_app(
    *,
    server_name: str,
    relay_schema: dict[str, Any],
    on_credentials_saved: CredentialsCallback | None = None,
    on_step_submitted: StepCallback | None = None,
    jwt_issuer: JWTIssuer | None = None,
    custom_credential_form_html: Callable[..., str] | None = None,
) -> tuple[Starlette, JWTIssuer]:
    """Create OAuth 2.1 Authorization Server Starlette app.

    Args:
        server_name: Identifier for the MCP server (used for JWT iss/aud).
        relay_schema: RelayConfigSchema dict describing the credential form.
        on_credentials_saved: Callback invoked with credentials dict after
            the user submits the form. Typically wraps ``write_config``.
            May return a ``next_step`` dict (e.g. ``{"type": "otp_required"}``)
            to trigger multi-step auth flows.
        on_step_submitted: Callback invoked with step input dict (e.g.
            ``{"otp_code": "12345"}`` or ``{"password": "secret"}``) when
            the user submits data to ``/otp``. Return ``None`` to complete
            the flow, ``{"type": "otp_required"|"password_required", ...}``
            to chain to another step, or ``{"type": "error", "text": "..."}``
            to reject the current input and allow retry. Callbacks that
            compare secrets MUST use ``secrets.compare_digest`` or similar
            timing-safe comparison to prevent timing attacks.
        jwt_issuer: Optional pre-created JWTIssuer. If None, one is created
            automatically using ``server_name``.
        custom_credential_form_html: Optional callable
            ``(schema, submit_url, *, prefill=None) -> html_string`` used to
            render GET /authorize. When provided, replaces the default
            ``render_credential_form`` output. Consumers (email, telegram)
            use this to inject rich UX (multi-account cards, tabs, domain
            detection) while reusing core OAuth plumbing. The returned HTML
            MUST include a form/fetch that POSTs JSON to ``submit_url``
            (which embeds the PKCE nonce). The optional ``prefill`` mapping
            carries values extracted from ``?prefill_<KEY>=<value>`` query
            params on the GET so consumers can render ``<input value="...">``
            for skret-derived fields the driver knows up front (e.g.
            telegram-user TELEGRAM_PHONE), letting the user click Connect
            instead of retyping them. Renderers may safely ignore prefill.

    Returns:
        ``(app, jwt_issuer)`` tuple. The ``jwt_issuer`` is needed by the
        transport layer to verify Bearer tokens on ``/mcp`` requests.
    """
    if jwt_issuer is None:
        jwt_issuer = JWTIssuer(server_name=server_name)

    # In-memory stores keyed by nonce / auth_code.
    # Each entry includes a ``created_at`` timestamp for TTL expiry.
    # Structure: {nonce: {client_id, redirect_uri, state, code_challenge, code_challenge_method, created_at}}
    pending_sessions: dict[str, dict[str, Any]] = {}
    # Structure: {auth_code: {code_challenge, code_challenge_method, created_at}}
    auth_codes: dict[str, dict[str, Any]] = {}

    # One pending multi-step session at a time. POST /otp has no sub in its
    # body, so we also capture the sub that opened this flow (via POST
    # /authorize → on_credentials_saved → otp_required NextStep) and thread
    # it into on_step_submitted as SubjectContext. Concurrent remote-relay
    # OTP flows are inherently serialized by this design — that's acceptable
    # for multi-step auth UX and prevents cross-user step corruption.
    # Keys: "active" (bool), "created_at" (monotonic), "attempts" (int),
    # "sub" (str, the JWT sub that owns this step session).
    _pending_step: dict[str, Any] = {}

    def _mark_pending_step(sub: str) -> None:
        """Activate the pending step session keyed by the authorize subject."""
        _pending_step["active"] = True
        _pending_step["created_at"] = time.monotonic()
        _pending_step["attempts"] = 0
        _pending_step["sub"] = sub

    def _clear_pending_step() -> None:
        """Xóa pending step session (sau khi complete hoặc expired)."""
        _pending_step.clear()

    def _prune_expired(store: dict[str, dict[str, Any]], ttl: float) -> None:
        """Remove entries older than *ttl* seconds."""
        now = time.monotonic()
        expired = [k for k, v in store.items() if now - v["created_at"] > ttl]
        for k in expired:
            del store[k]

    def _base_url(request: Request) -> str:
        """Derive the public base URL from the request.

        Resolution order:
        1. ``PUBLIC_URL`` env var -- trusted, explicit. This is the
           remote-deploy convention (oci-vm-prod) where the container sits
           behind CF Tunnel -> Caddy (HTTP internal) but is served to clients
           over HTTPS. Starlette's ``request.base_url`` reflects the scheme
           the ASGI server saw (HTTP from the proxy), so without this override
           OAuth 2.1 metadata would leak ``http://`` as the issuer and strict
           clients reject the discovery document.
        2. Starlette ``request.base_url`` -- uses ``X-Forwarded-Proto`` /
           ``X-Forwarded-Host`` when ``ProxyHeadersMiddleware`` is mounted,
           otherwise the raw socket scheme.
        """
        public_url = os.environ.get("PUBLIC_URL")
        if public_url:
            return public_url.rstrip("/")
        return str(request.base_url).rstrip("/")

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------

    async def authorize_get(request: Request) -> HTMLResponse | JSONResponse:
        """GET /authorize -- render the credential form."""
        params = request.query_params
        client_id = params.get("client_id")
        redirect_uri = params.get("redirect_uri")
        state = params.get("state")
        code_challenge = params.get("code_challenge")
        code_challenge_method = params.get("code_challenge_method", "S256")

        if not all([client_id, redirect_uri, state, code_challenge]):
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Missing required parameters"},
                status_code=400,
            )

        # Extract prefill values from query: ``?prefill_<KEY>=<VALUE>``. The
        # driver builds these from skret so the user only types what skret
        # cannot supply (OTP / 2FA password). Renderers receive a flat
        # ``{KEY: VALUE}`` dict; values land as HTML-escaped ``value`` attrs
        # on matching inputs in the form.
        prefill: dict[str, str] = {}
        for k in params.keys():
            if k.startswith("prefill_"):
                prefill[k.removeprefix("prefill_")] = params[k]

        # Create a session nonce that ties the form submission to this PKCE flow
        # and a fresh per-authorize ``sub`` that will be passed to the credential
        # save callback and stamped onto the JWT at /token. Generating the sub
        # here (not at /token) is what makes multi-user isolation actually work:
        # two concurrent browser sessions get two distinct subjects, so the
        # consumer's per-user credential store writes to two different keys.
        nonce = secrets.token_urlsafe(32)
        sub = secrets.token_urlsafe(16)
        pending_sessions[nonce] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "created_at": time.monotonic(),
            "sub": sub,
        }

        _prune_expired(pending_sessions, _SESSION_TTL_S)

        base = _base_url(request)
        submit_url = f"{base}/authorize?nonce={nonce}"
        if custom_credential_form_html is not None:
            html_content = custom_credential_form_html(relay_schema, submit_url, prefill=prefill)
        else:
            html_content = render_credential_form(relay_schema, submit_url=submit_url, prefill=prefill)
        return HTMLResponse(html_content)

    async def authorize_post(request: Request) -> JSONResponse:
        """POST /authorize -- receive credentials, save, return redirect URL with auth code."""
        nonce = request.query_params.get("nonce")
        if not nonce or nonce not in pending_sessions:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid or expired nonce"},
                status_code=400,
            )

        session = pending_sessions.pop(nonce)

        # Check TTL
        if time.monotonic() - session["created_at"] > _SESSION_TTL_S:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Session expired"},
                status_code=400,
            )

        try:
            credentials: dict[str, str] = await request.json()
        except Exception:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid JSON body"},
                status_code=400,
            )

        # Reset stale completion markers from previous authorize submits.
        # _setup_status is closure-scoped, so a key flipped to "complete"
        # by a prior background poll (e.g. Outlook device code finished
        # on the first attempt) would otherwise persist into the next
        # form submit. The frontend renders a fresh oauth_device_code UI
        # and starts polling /setup-status, which returns the stale
        # "complete" within a few seconds and triggers a premature
        # redirect. Reset all keys to "idle" so each submit starts from
        # a clean state.
        for _k in list(_setup_status.keys()):
            _setup_status[_k] = "idle"

        # Save credentials via callback. Callback may return a dict with
        # next_step info (e.g., GDrive OAuth device code to show in the form).
        # The ``SubjectContext`` carries the per-authorize sub so the consumer
        # can persist credentials keyed by subject, matching the JWT that
        # /token will issue.
        context: SubjectContext = {"sub": session["sub"]}
        next_step: dict[str, Any] | None = None
        if on_credentials_saved is not None:
            try:
                result = on_credentials_saved(credentials, context)
                if inspect.iscoroutine(result):
                    result = await result
                if isinstance(result, dict):
                    next_step = cast("dict[str, Any]", result)
            except Exception:
                logger.exception("on_credentials_saved callback failed")
                return JSONResponse(
                    {"error": "server_error", "error_description": "Failed to save credentials"},
                    status_code=500,
                )

        if next_step and next_step.get("type") == "error":
            return JSONResponse(
                {"ok": False, "error": next_step.get("text", "Unknown error")},
            )

        # Generate auth code. Copy ``sub`` so /token issues the JWT with the
        # same subject the credentials were saved under.
        auth_code = secrets.token_urlsafe(32)
        auth_codes[auth_code] = {
            "code_challenge": session["code_challenge"],
            "code_challenge_method": session["code_challenge_method"],
            "created_at": time.monotonic(),
            "sub": session["sub"],
        }

        _prune_expired(auth_codes, _AUTH_CODE_TTL_S)

        redirect_uri = session["redirect_uri"]
        state = session["state"]
        separator = "&" if "?" in redirect_uri else "?"
        redirect_url = f"{redirect_uri}{separator}code={auth_code}&state={state}"

        response_body: dict = {"ok": True, "redirect_url": redirect_url}
        if next_step:
            response_body["next_step"] = next_step
            # Nếu next_step yêu cầu input thêm (OTP hoặc 2FA password),
            # activate pending step session để /otp endpoint chấp nhận input.
            # Capture the authorize-session sub so /otp can thread the correct
            # SubjectContext into on_step_submitted — the browser POSTs step
            # data without a sub, so this field is the only binding.
            if next_step.get("type") in ("otp_required", "password_required"):
                _mark_pending_step(session["sub"])

        return JSONResponse(response_body)

    async def authorize(request: Request) -> HTMLResponse | JSONResponse:
        """Dispatch GET/POST on /authorize."""
        if request.method == "GET":
            return await authorize_get(request)
        return await authorize_post(request)

    async def token(request: Request) -> JSONResponse:
        """POST /token -- exchange auth code + PKCE code_verifier for JWT."""
        try:
            form = await request.form()
        except Exception:
            return JSONResponse({"error": "invalid_request"}, status_code=400)

        grant_type = form.get("grant_type")
        if grant_type != "authorization_code":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

        code = form.get("code")
        code_verifier = form.get("code_verifier")

        if not code or not code_verifier:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Missing code or code_verifier"},
                status_code=400,
            )

        code = str(code)
        code_verifier = str(code_verifier)

        # Look up auth code
        entry = auth_codes.pop(code, None)
        if entry is None:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        # Check TTL
        if time.monotonic() - entry["created_at"] > _AUTH_CODE_TTL_S:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        # Verify PKCE
        method = entry["code_challenge_method"]
        if method != "S256":
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Only S256 is supported"},
                status_code=400,
            )

        if not _s256_verify(code_verifier, entry["code_challenge"]):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        # Issue JWT with the subject bound to this authorize session. Previously
        # this was the static string "local-user", which collapsed every browser
        # session into one subject and defeated any per-user credential scoping
        # attempted by remote-relay consumers. The new flow mints a fresh sub in
        # authorize_get, carries it through on_credentials_saved via
        # SubjectContext, and stamps it onto the JWT here.
        access_token = jwt_issuer.issue_access_token(sub=entry["sub"])

        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        )

    async def otp_handler(request: Request) -> JSONResponse:
        """POST /otp -- receive multi-step auth input (OTP code or 2FA password).

        Protocol (order of checks):
        1. No active step session -> 400 ``invalid_request`` (no state change).
        2. Pending session expired (>``_OTP_TIMEOUT_S``s) -> clear, 400.
        3. Parse JSON body -> 400 on invalid (do NOT increment attempts or
           clear session; malformed input should not burn user's retry quota).
        4. Increment attempts counter.
        5. Attempts exceeded (>``_OTP_MAX_ATTEMPTS``) -> clear, 400.
        6. Call ``on_step_submitted(step_data)``:
            - ``None`` -> clear pending, return ``{"ok": true}`` (complete).
            - ``{"type": "error", "text": ...}`` -> return ``{"ok": false,
              "error": ...}`` (keep pending, allow retry; attempts already
              incremented before the callback).
            - ``{"type": "otp_required"|"password_required", ...}`` -> reset
              counters (new step), return ``{"ok": true, "next_step": {...}}``.
        """
        # 1. Active session check.
        if not _pending_step.get("active"):
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "No active step session",
                },
                status_code=400,
            )

        # 2. Timeout check.
        created_at = _pending_step.get("created_at", 0.0)
        if time.monotonic() - created_at > _OTP_TIMEOUT_S:
            _clear_pending_step()
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "Step session expired",
                },
                status_code=400,
            )

        # 3. Parse JSON body BEFORE incrementing attempts. Malformed input
        # should not consume the user's retry quota nor clear the session.
        try:
            step_data: dict[str, str] = await request.json()
        except Exception:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid JSON body"},
                status_code=400,
            )

        # 4. Increment attempts counter (count every valid-JSON submit).
        _pending_step["attempts"] = _pending_step.get("attempts", 0) + 1

        # 5. Attempt limit check.
        if _pending_step["attempts"] > _OTP_MAX_ATTEMPTS:
            _clear_pending_step()
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "Too many attempts",
                },
                status_code=400,
            )

        # Thread the sub captured when this step session was opened into the
        # callback so consumers (telegram per-user Telethon) can route this
        # OTP / 2FA input to the correct user's in-flight sign-in.
        step_sub = str(_pending_step.get("sub", ""))
        step_context: SubjectContext = {"sub": step_sub}

        next_step: dict[str, Any] | None = None
        if on_step_submitted is not None:
            try:
                result = on_step_submitted(step_data, step_context)
                if inspect.iscoroutine(result):
                    result = await result
                if isinstance(result, dict):
                    next_step = cast("dict[str, Any]", result)
            except Exception:
                logger.exception("on_step_submitted callback failed")
                return JSONResponse(
                    {
                        "error": "server_error",
                        "error_description": "Failed to process step input",
                    },
                    status_code=500,
                )

        # Error from callback: keep pending, allow retry (don't clear).
        if next_step is not None and next_step.get("type") == "error":
            return JSONResponse({"ok": False, "error": next_step.get("text", "Invalid input")})

        # Chain to next step: reset counters so the new step gets its own quota.
        # Preserve the original sub so the whole multi-step chain stays under
        # the same user.
        if next_step is not None and next_step.get("type") in (
            "otp_required",
            "password_required",
        ):
            _mark_pending_step(step_sub)
            return JSONResponse({"ok": True, "next_step": next_step})

        # Completion (callback returned None or unknown dict type).
        _clear_pending_step()
        return JSONResponse({"ok": True})

    async def well_known_as(request: Request) -> JSONResponse:
        """GET /.well-known/oauth-authorization-server -- RFC 8414."""
        base = _base_url(request)
        return JSONResponse(authorization_server_metadata(base))

    async def well_known_pr(request: Request) -> JSONResponse:
        """GET /.well-known/oauth-protected-resource -- RFC 9728."""
        base = _base_url(request)
        return JSONResponse(
            protected_resource_metadata(
                resource=base,
                authorization_servers=[base],
            )
        )

    # In-memory setup status (set by background tasks via mark_setup_complete
    # or mark_setup_failed). Values: "idle", "complete", or "error:<message>".
    _setup_status: dict[str, str] = {"gdrive": "idle"}

    def mark_setup_complete(key: str = "gdrive") -> None:
        """Mark a background setup step as complete (called externally)."""
        _setup_status[key] = "complete"

    def mark_setup_failed(key: str = "gdrive", error: str = "unknown error") -> None:
        """Mark a background setup step as failed (called externally).

        The status is encoded as ``"error:<message>"`` so the frontend poll
        handler can detect failure and surface the message to the user,
        stopping the spinner that would otherwise wait forever.
        """
        # Sanitize: collapse whitespace so the error string is single-line
        # (the frontend inlines it). Strip colons in the user-visible part
        # only by replacing the rare ``error:`` prefix in callback text, to
        # avoid double-prefixing.
        message = " ".join(str(error).split()) or "unknown error"
        _setup_status[key] = f"error:{message}"

    async def setup_status(request: Request) -> JSONResponse:
        """GET /setup-status -- polled by the form to detect GDrive auth completion."""
        return JSONResponse(_setup_status)

    async def root(request: Request):
        """GET / -- auto-generate PKCE and redirect to /authorize.

        The ``/authorize`` endpoint requires 4 PKCE parameters (``client_id``,
        ``redirect_uri``, ``state``, ``code_challenge``). Users arriving from
        a log line or bookmark have no way to construct those parameters
        themselves, so the server bootstraps a default ``local-browser``
        client here: generate random state + S256 challenge, redirect to
        ``/authorize`` with valid params, and on success return to
        ``/callback-done`` for a friendly close message.

        This keeps the one-URL UX ("open http://... in browser") working
        without exposing the raw OAuth machinery to end users.
        """
        from starlette.responses import RedirectResponse

        base = _base_url(request)

        # Generate PKCE pair for this bootstrap session.
        # We reuse the ``pending_sessions`` store keyed by nonce so the
        # normal ``authorize_get`` path can consume it. But ``authorize_get``
        # itself generates the nonce + session, so we just build the
        # redirect URL with fresh PKCE params.
        _code_verifier = secrets.token_urlsafe(64)
        _challenge_digest = hashlib.sha256(_code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(_challenge_digest).rstrip(b"=").decode("ascii")
        state = secrets.token_urlsafe(16)

        from urllib.parse import urlencode

        redirect_uri = f"{base}/callback-done"
        params = urlencode(
            {
                "client_id": "local-browser",
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return RedirectResponse(url=f"/authorize?{params}", status_code=302)

    async def callback_done(request: Request) -> HTMLResponse:
        """GET /callback-done -- friendly "tab can be closed" page.

        ``/authorize`` POST returns a ``redirect_url`` that the frontend uses
        to finalize the PKCE exchange. When the bootstrap flow from ``/``
        completes, the browser lands here. This page exists purely as a
        terminal landing so the bare URL doesn't 404.
        """
        html_content = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>Setup complete</title>"
            "<style>body{font-family:-apple-system,Segoe UI,sans-serif;"
            "background:#111;color:#eee;display:flex;align-items:center;"
            "justify-content:center;height:100vh;margin:0}"
            ".box{text-align:center;padding:2rem;border:1px solid #333;"
            "border-radius:8px;background:#1a1a1a}"
            "h1{color:#34c759;margin:0 0 0.5rem}p{color:#aaa;margin:0}"
            "</style></head><body><div class='box'>"
            "<h1>Setup complete</h1>"
            "<p>You can close this tab.</p>"
            "</div></body></html>"
        )
        return HTMLResponse(html_content)

    async def register_handler(request: Request) -> JSONResponse:
        """RFC 7591 Dynamic Client Registration (echo-style).

        Fixed public ``client_id`` (``local-browser``). Mirrors the
        client's submitted metadata back with the fixed id so MCP clients
        that require DCR can bootstrap OAuth without a registration error.
        """
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        if not isinstance(body, dict):
            body = {}
        redirect_uris = body.get("redirect_uris") if isinstance(body.get("redirect_uris"), list) else []
        grant_types = body.get("grant_types") if isinstance(body.get("grant_types"), list) else ["authorization_code"]
        response_types = body.get("response_types") if isinstance(body.get("response_types"), list) else ["code"]
        client_name = body.get("client_name") if isinstance(body.get("client_name"), str) else "mcp-client"
        return JSONResponse(
            {
                "client_id": "local-browser",
                "client_name": client_name,
                "redirect_uris": redirect_uris,
                "grant_types": grant_types,
                "response_types": response_types,
                "token_endpoint_auth_method": "none",
            },
            status_code=201,
        )

    # ------------------------------------------------------------------
    # Build Starlette app
    # ------------------------------------------------------------------

    routes = [
        Route("/", root, methods=["GET"]),
        Route("/authorize", authorize, methods=["GET", "POST"]),
        Route("/otp", otp_handler, methods=["POST"]),
        Route("/token", token, methods=["POST"]),
        Route("/register", register_handler, methods=["POST"]),
        Route("/setup-status", setup_status, methods=["GET"]),
        Route("/callback-done", callback_done, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", well_known_as, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", well_known_pr, methods=["GET"]),
    ]

    app = Starlette(routes=routes)

    # Expose mark_setup_complete / mark_setup_failed on the app for
    # external callers (see transport/local_server.py for wiring).
    app.state.mark_setup_complete = mark_setup_complete  # type: ignore[attr-defined]
    app.state.mark_setup_failed = mark_setup_failed  # type: ignore[attr-defined]

    return app, jwt_issuer
