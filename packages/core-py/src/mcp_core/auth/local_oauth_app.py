"""Local OAuth 2.1 Authorization Server as a Starlette ASGI app.

Provides a self-hosted Authorization Server for single-user MCP servers.
Implements the OAuth 2.1 PKCE flow with credential collection via a
browser-rendered form.

Routes:
- GET  /authorize                               -- Render credential form
- POST /authorize                               -- Save credentials, return auth code
- POST /otp                                     -- Submit multi-step credential (OTP / 2FA password)
- POST /token                                   -- Exchange auth code + PKCE verifier for JWT
- GET  /setup-status                            -- Poll background setup completion
- GET  /.well-known/oauth-authorization-server   -- RFC 8414 metadata
- GET  /.well-known/oauth-protected-resource     -- RFC 9728 metadata

The /mcp endpoint is NOT included -- it is mounted by the transport layer.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import Any, Union

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
CredentialsCallback = Callable[[dict[str, str]], Union[dict | None, Awaitable[dict | None]]]
StepCallback = Callable[[dict[str, str]], Union[dict | None, Awaitable[dict | None]]]


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

    # Single-user local mode: one pending multi-step session at a time.
    # Keys: "active" (bool), "created_at" (monotonic), "attempts" (int).
    # Được set khi ``on_credentials_saved`` (hoặc ``on_step_submitted``)
    # trả về ``next_step`` type ``otp_required`` hoặc ``password_required``.
    _pending_step: dict[str, Any] = {}

    def _mark_pending_step() -> None:
        """Đánh dấu pending step session đang active (reset counters)."""
        _pending_step["active"] = True
        _pending_step["created_at"] = time.monotonic()
        _pending_step["attempts"] = 0

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
        """Derive the public base URL from the request."""
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

        # Create a session nonce that ties the form submission to this PKCE flow
        nonce = secrets.token_urlsafe(32)
        pending_sessions[nonce] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "created_at": time.monotonic(),
        }

        _prune_expired(pending_sessions, _SESSION_TTL_S)

        base = _base_url(request)
        submit_url = f"{base}/authorize?nonce={nonce}"
        html_content = render_credential_form(relay_schema, submit_url=submit_url)
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

        # Save credentials via callback. Callback may return a dict with
        # next_step info (e.g., GDrive OAuth device code to show in the form).
        next_step: dict | None = None
        if on_credentials_saved is not None:
            try:
                result = on_credentials_saved(credentials)
                if inspect.iscoroutine(result):
                    result = await result
                if isinstance(result, dict):
                    next_step = result
            except Exception:
                logger.exception("on_credentials_saved callback failed")
                return JSONResponse(
                    {"error": "server_error", "error_description": "Failed to save credentials"},
                    status_code=500,
                )

        # Generate auth code
        auth_code = secrets.token_urlsafe(32)
        auth_codes[auth_code] = {
            "code_challenge": session["code_challenge"],
            "code_challenge_method": session["code_challenge_method"],
            "created_at": time.monotonic(),
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
            if next_step.get("type") in ("otp_required", "password_required"):
                _mark_pending_step()

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

        # Issue JWT -- single-user local mode, sub is always "local-user"
        access_token = jwt_issuer.issue_access_token(sub="local-user")

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

        next_step: dict | None = None
        if on_step_submitted is not None:
            try:
                result = on_step_submitted(step_data)
                if inspect.iscoroutine(result):
                    result = await result
                if isinstance(result, dict):
                    next_step = result
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
        if next_step is not None and next_step.get("type") in (
            "otp_required",
            "password_required",
        ):
            _mark_pending_step()
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

    # In-memory setup status (set by background tasks via mark_setup_complete)
    _setup_status: dict[str, str] = {"gdrive": "idle"}

    def mark_setup_complete(key: str = "gdrive") -> None:
        """Mark a background setup step as complete (called externally)."""
        _setup_status[key] = "complete"

    async def setup_status(request: Request) -> JSONResponse:
        """GET /setup-status -- polled by the form to detect GDrive auth completion."""
        return JSONResponse(_setup_status)

    # ------------------------------------------------------------------
    # Build Starlette app
    # ------------------------------------------------------------------

    routes = [
        Route("/authorize", authorize, methods=["GET", "POST"]),
        Route("/otp", otp_handler, methods=["POST"]),
        Route("/token", token, methods=["POST"]),
        Route("/setup-status", setup_status, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", well_known_as, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", well_known_pr, methods=["GET"]),
    ]

    app = Starlette(routes=routes)

    # Expose mark_setup_complete on the app for external callers
    app.state.mark_setup_complete = mark_setup_complete  # type: ignore[attr-defined]

    return app, jwt_issuer
