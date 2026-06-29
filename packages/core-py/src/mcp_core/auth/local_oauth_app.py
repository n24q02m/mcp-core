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
from collections.abc import Awaitable, Callable, Iterable
from html import escape as _escape
from typing import Any, Union, cast

from loguru import logger
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from mcp_core.auth.credential_form import is_oauth_field, is_secret_field, render_credential_form
from mcp_core.auth.stable_sub import derive_stable_sub
from mcp_core.auth.relay_login import (
    configure_relay_login,
    login_get_handler,
    login_post_handler,
    require_relay_session,
)
from mcp_core.auth.well_known import (
    derive_base_url,
    authorization_server_metadata,
    protected_resource_metadata,
)
from mcp_core.oauth.jwt_issuer import JWTIssuer
from mcp_core.storage.config_file import (
    mark_setup_complete as _mark_config_setup_complete,
)

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
    stable_sub_enabled: bool = False,
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
            automatically using ``server_name`` -- EdDSA derived from
            ``CREDENTIAL_SECRET`` in HTTP multi-user mode, else RS256 on disk.
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
        # Mirror core-ts: in HTTP multi-user mode the fallback issuer derives a
        # stable EdDSA key from CREDENTIAL_SECRET (survives container
        # recreation); unset -> RS256-on-disk local path.
        jwt_issuer = JWTIssuer(server_name=server_name, credential_secret=os.environ.get("CREDENTIAL_SECRET"))

    # In-memory stores keyed by nonce / auth_code.
    # Each entry includes a ``created_at`` timestamp for TTL expiry.
    # Structure: {nonce: {client_id, redirect_uri, state, code_challenge, code_challenge_method, created_at}}
    pending_sessions: dict[str, dict[str, Any]] = {}
    # Structure: {auth_code: {code_challenge, code_challenge_method, created_at}}
    auth_codes: dict[str, dict[str, Any]] = {}
    # Server-side prefill keyed by OAuth ``state`` token. The E2E driver POSTs
    # skret-derived form values to /authorize/prefill BEFORE announcing the
    # /authorize URL, so credentials never appear in the URL the user opens.
    # Without this, ``?prefill_TELEGRAM_PHONE=%2B84...`` would leak into
    # browser history, server access logs, screenshots, and HTTP referrer.
    # Structure: {state: {data: {KEY: VALUE}, created_at: monotonic}}
    pending_prefills: dict[str, dict[str, Any]] = {}
    _PREFILL_TTL_S = 300.0

    # Edge auth password gate (per spec 2026-05-01-stdio-pure-http-multiuser
    # §4.2.1). When ``MCP_RELAY_PASSWORD`` is set, /authorize GET + POST and
    # /authorize/prefill are fronted by a thin cookie-session check. Empty
    # password disables the gate. Configured here so test setups that build
    # multiple apps in one process get fresh state per ``create_local_oauth_app``
    # call (relay_login keeps a single shared password — intentional, since in
    # deploy each container hosts one app).
    _relay_password = os.environ.get("MCP_RELAY_PASSWORD", "")
    configure_relay_login(_relay_password)

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
        # ⚡ Bolt: Prune in-place using dict comprehension to avoid intermediate list
        remaining = {k: v for k, v in store.items() if now - v["created_at"] <= ttl}
        if len(remaining) < len(store):
            store.clear()
            store.update(remaining)

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

        # Resolve prefill values for the form. Two channels, in priority order:
        #   1. Server-side store keyed by ``state`` -- written by the E2E driver
        #      via POST /authorize/prefill BEFORE the user opens the URL. This
        #      is the safe channel; nothing leaves the server boundary.
        #   2. URL query string ``?prefill_<KEY>=<VALUE>`` -- legacy fallback for
        #      callers that have not migrated yet. Deprecated.
        # Renderers receive a flat ``{KEY: VALUE}`` dict; values land as
        # HTML-escaped ``value`` attrs on matching inputs in the form.
        prefill: dict[str, str] = {}
        _prune_expired(pending_prefills, _PREFILL_TTL_S)
        stored = pending_prefills.pop(state, None) if state else None
        if stored:
            prefill.update(stored.get("data", {}))
        else:
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

        base = derive_base_url(request)
        submit_url = f"{base}/authorize?nonce={nonce}"
        if custom_credential_form_html is not None:
            html_content = custom_credential_form_html(relay_schema, submit_url, prefill=prefill)
        else:
            html_content = render_credential_form(
                relay_schema,
                submit_url=submit_url,
                prefill=prefill,
                include_username_field=stable_sub_enabled,
            )
        return HTMLResponse(html_content, headers={"X-Frame-Options": "DENY"})

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

        # Reserved partition key: pop it so it is never persisted as a provider
        # credential. When stable-sub is enabled and a username was supplied,
        # override the random per-authorize sub with a STABLE one derived from it
        # (same username -> same per-sub bucket across re-auth and devices).
        # Blank username or disabled flag -> keep the random sub (unchanged).
        _username = str(credentials.pop("__sub_username", "")).strip()
        if stable_sub_enabled and _username:
            session["sub"] = derive_stable_sub(_username, server_name, os.environ.get("CREDENTIAL_SECRET"))

        # Reset stale completion markers from previous authorize submits.
        # _setup_status is closure-scoped, so a key flipped to "complete"
        # by a prior background poll (e.g. Outlook device code finished
        # on the first attempt) would otherwise persist into the next
        # form submit. The frontend renders a fresh oauth_device_code UI
        # and starts polling /setup-status, which returns the stale
        # "complete" within a few seconds and triggers a premature
        # redirect. Reset all keys to "idle" so each submit starts from
        # a clean state.
        _setup_status.update(dict.fromkeys(_setup_status, "idle"))

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
                if inspect.isawaitable(result):
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

        # Mark the persistent ``_setup_complete`` flag once the user has
        # successfully submitted the form. For single-step flows this is the
        # final state. For multi-step flows (OTP / 2FA), defer marking until
        # the chain completes — see ``otp_handler``. The flag lets
        # ``runLocalServer``'s ``is_schema_complete`` gate distinguish "user
        # finished the form" from "config.enc has values from peer-share".
        is_multi_step = next_step is not None and next_step.get("type") in (
            "otp_required",
            "password_required",
        )
        if not is_multi_step:
            try:
                _mark_config_setup_complete(server_name)
            except Exception:  # noqa: BLE001
                logger.opt(exception=True).warning("Failed to mark _setup_complete=true for {}", server_name)

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

    async def authorize(request: Request):
        """Dispatch GET/POST on /authorize.

        When ``MCP_RELAY_PASSWORD`` is set, requests without a valid
        ``mcp_relay_session`` cookie are redirected to ``/login`` (handled
        inside ``require_relay_session``).
        """
        if _relay_password:
            gated = await require_relay_session(
                dict(request.cookies), str(request.url.path) + (f"?{request.url.query}" if request.url.query else "")
            )
            if gated is not None:
                return gated
        if request.method == "GET":
            return await authorize_get(request)
        return await authorize_post(request)

    async def authorize_prefill(request: Request):
        """POST /authorize/prefill -- driver-only side channel for form prefill.

        Stores form prefill values keyed by the OAuth ``state`` token chosen by
        the client. ``GET /authorize?state=<X>`` then hydrates the form on
        render — credentials never appear in the URL the user opens.

        Gated by the same relay-password cookie as ``/authorize`` itself when
        ``MCP_RELAY_PASSWORD`` is set.
        """
        if _relay_password:
            gated = await require_relay_session(
                dict(request.cookies), str(request.url.path) + (f"?{request.url.query}" if request.url.query else "")
            )
            if gated is not None:
                return gated
        state = request.query_params.get("state")
        if not state:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Missing state"},
                status_code=400,
            )
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Body must be JSON object"},
                status_code=400,
            )
        if not isinstance(body, dict):
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Body must be JSON object"},
                status_code=400,
            )
        # Coerce all values to string + drop empties so blank ``value=""`` attrs
        # don't shadow placeholder text in the rendered form.
        data: dict[str, str] = {}
        for k, v in body.items():
            if v is not None and len(str(v)) > 0:
                data[str(k)] = str(v)
        pending_prefills[state] = {"data": data, "created_at": time.monotonic()}
        _prune_expired(pending_prefills, _PREFILL_TTL_S)
        return JSONResponse({}, status_code=204)

    def _issue_token_response(sub: str) -> JSONResponse:
        """Build the standard /token success body for *sub*.

        Issues a fresh access token AND a fresh refresh token. The refresh
        token lets long-running MCP clients renew the 1h access token without
        re-running the browser PKCE flow (issue #261). ``scope`` advertises
        ``offline_access`` so clients know a refresh token was granted.
        """
        access_token = jwt_issuer.issue_access_token(sub=sub)
        refresh_token = jwt_issuer.issue_refresh_token(sub=sub)
        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": refresh_token,
                "scope": "offline_access",
            }
        )

    async def token(request: Request) -> JSONResponse:
        """POST /token -- authorization_code exchange or refresh_token rotation."""
        try:
            form = await request.form()
        except Exception:
            return JSONResponse({"error": "invalid_request"}, status_code=400)

        grant_type = form.get("grant_type")
        if grant_type == "refresh_token":
            return _handle_refresh_token(form)
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
        return _issue_token_response(entry["sub"])

    def _handle_refresh_token(form: Any) -> JSONResponse:
        """Handle ``grant_type=refresh_token`` (RFC 6749 §6) statelessly.

        Verifies the presented refresh token's signature / iss / aud / exp /
        ``typ`` via the JWT issuer (no server-side store), extracts ``sub``,
        and issues a NEW access token AND a NEW refresh token (rotation). The
        refresh token is self-contained, so rotation here is stateless: the
        old refresh token simply expires on its own 30-day clock; clients are
        expected to replace it with the rotated one returned below.
        """
        refresh_token = form.get("refresh_token")
        if not refresh_token:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Missing refresh_token"},
                status_code=400,
            )
        try:
            claims = jwt_issuer.verify_refresh_token(str(refresh_token))
        except Exception:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        return _issue_token_response(str(claims["sub"]))

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
                if inspect.isawaitable(result):
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
        # Mark persistent _setup_complete flag now that the multi-step chain
        # has finished — single-step counterpart lives in authorize_post.
        try:
            _mark_config_setup_complete(server_name)
        except Exception:  # noqa: BLE001
            logger.opt(exception=True).warning("Failed to mark _setup_complete=true for {}", server_name)
        _clear_pending_step()
        return JSONResponse({"ok": True})

    async def well_known_as(request: Request) -> JSONResponse:
        """GET /.well-known/oauth-authorization-server -- RFC 8414."""
        base = derive_base_url(request)
        return JSONResponse(authorization_server_metadata(base))

    async def well_known_pr(request: Request) -> JSONResponse:
        """GET /.well-known/oauth-protected-resource -- RFC 9728."""
        base = derive_base_url(request)
        return JSONResponse(
            protected_resource_metadata(
                resource=base,
                authorization_servers=[base],
            )
        )

    async def well_known_jwks(request: Request) -> JSONResponse:
        """GET /.well-known/jwks.json -- public signing keys (RFC 7517)."""
        return JSONResponse(jwt_issuer.get_jwks())

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

        base = derive_base_url(request)

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
        return HTMLResponse(html_content, headers={"X-Frame-Options": "DENY"})

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

    async def login_get(request: Request):
        """GET /login -- render the relay-password form."""
        next_param = request.query_params.get("next", "/authorize")
        return await login_get_handler(next_param)

    async def login_post(request: Request):
        """POST /login -- verify the relay password and issue a session cookie."""
        form = await request.form()
        ip = request.client.host if request.client else "unknown"
        return await login_post_handler(dict(form), ip=ip)

    routes = [
        Route("/", root, methods=["GET"]),
        Route("/login", login_get, methods=["GET"]),
        Route("/login", login_post, methods=["POST"]),
        Route("/authorize", authorize, methods=["GET", "POST"]),
        Route("/authorize/prefill", authorize_prefill, methods=["POST"]),
        Route("/otp", otp_handler, methods=["POST"]),
        Route("/token", token, methods=["POST"]),
        Route("/register", register_handler, methods=["POST"]),
        Route("/setup-status", setup_status, methods=["GET"]),
        Route("/callback-done", callback_done, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", well_known_as, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", well_known_pr, methods=["GET"]),
        Route("/.well-known/jwks.json", well_known_jwks, methods=["GET"]),
    ]

    app = Starlette(routes=routes)

    # Expose mark_setup_complete / mark_setup_failed on the app for
    # external callers (see transport/local_server.py for wiring).
    app.state.mark_setup_complete = mark_setup_complete  # type: ignore[attr-defined]
    app.state.mark_setup_failed = mark_setup_failed  # type: ignore[attr-defined]

    return app, jwt_issuer


# ---------------------------------------------------------------------------
# D7 — Pre-fill renderer + form-submission merger.
#
# These helpers are exported as standalone primitives for consumers that build
# their own ``customCredentialFormHtml`` renderer or POST handler. They are
# intentionally NOT wired into the default ``authorize_get`` / ``authorize_post``
# above — that path stays on ``render_credential_form`` for legacy parity. New
# consumers (transparent-bridge Wave 1) compose ``render_field`` per field to
# get secret-aware rendering and then call ``merge_submission`` to merge the
# POST body with their stored ``config.enc`` so a missing secret in the body
# preserves the previously stored value instead of clearing it.
# ---------------------------------------------------------------------------

_SECRET_PLACEHOLDER = "••••••••(configured)"


def _field_name(field: dict) -> str:
    """Return the canonical config key for a relay field.

    Two schema styles coexist in the codebase:
      * ``RelayConfigField`` (D7, ``credential_form.RelayConfigField``) uses
        ``name`` per the new spec.
      * Legacy ``ConfigField`` schemas (consumed by ``render_credential_form``)
        use ``key``.

    The helpers below accept both so a consumer can mix or migrate without
    rewriting field dicts. ``name`` wins when both are present.
    """
    return str(field.get("name") or field.get("key") or "")


def render_field(field: dict, current_value: Any) -> str:
    """Render an HTML ``<label>+<input>`` for a single relay field.

    Rules per D7:
      - oauth_field: render Re-authorize button (no plaintext exposed)
      - secret + value present: placeholder, empty input, "Replace" checkbox
      - secret + no value: empty input with field label as placeholder
      - non-secret: pre-fill with ``current_value`` as input ``value`` attr
    """
    name = _field_name(field)
    label = field.get("label", name)
    field_type = field.get("type", "text")

    if is_oauth_field(field):
        status = "Connected" if current_value else "Not connected"
        return (
            f'<div class="field oauth-field"><label>{_escape(label)}</label> '
            f'<span class="oauth-status">{status}</span> '
            f'<button type="button" class="oauth-reauth" data-field="{_escape(name)}" aria-label="Re-authorize {_escape(label)}">'
            f"Re-authorize</button></div>"
        )

    if is_secret_field(field):
        if current_value:
            return (
                f'<div class="field secret-field"><label for="field-{_escape(name)}">{_escape(label)}</label> '
                f'<input id="field-{_escape(name)}" type="password" name="{_escape(name)}" value="" '
                f'placeholder="{_escape(_SECRET_PLACEHOLDER)}" '
                f'data-secret-configured="true"> '
                f'<label for="replace-{_escape(name)}" class="replace-toggle"><input id="replace-{_escape(name)}" type="checkbox" '
                f'name="__replace_{_escape(name)}" value="1"> Replace this credential</label>'
                f"</div>"
            )
        return (
            f'<div class="field secret-field"><label for="field-{_escape(name)}">{_escape(label)}</label> '
            f'<input id="field-{_escape(name)}" type="password" name="{_escape(name)}" value="" '
            f'placeholder="{_escape(label)}"></div>'
        )

    value_attr = _escape(str(current_value)) if current_value is not None else ""
    return (
        f'<div class="field"><label for="field-{_escape(name)}">{_escape(label)}</label> '
        f'<input id="field-{_escape(name)}" type="{_escape(field_type)}" name="{_escape(name)}" '
        f'value="{value_attr}"></div>'
    )


def merge_submission(
    current: dict[str, Any],
    submitted: dict[str, Any],
    schema_fields: Iterable[dict],
) -> dict[str, Any]:
    """Merge a form submission into the current config per D7 rules.

    Behavior:
      - Empty secret -> preserve the existing value (avoid clearing on a
        re-submit where the user did not retype the credential).
      - Non-empty secret -> replace.
      - Non-secret -> always replace (including with an empty string, so the
        user can intentionally blank a field).
      - oauth_field -> ignored here; OAuth fields are managed by their own
        Re-authorize flow, never by raw form input.
    """
    result = dict(current)
    for field in schema_fields:
        name = _field_name(field)
        if not name:
            continue
        if is_oauth_field(field):
            continue
        new_value = submitted.get(name, "")
        if is_secret_field(field):
            if new_value == "" or new_value is None:
                # Preserve old.
                continue
            result[name] = new_value
        else:
            result[name] = new_value
    return result
