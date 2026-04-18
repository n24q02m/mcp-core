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
_OTP_TIMEOUT_S = 300
_OTP_MAX_ATTEMPTS = 5

CredentialsCallback = Callable[[dict[str, str]], Union[dict | None, Awaitable[dict | None]]]
StepCallback = Callable[[dict[str, str]], Union[dict | None, Awaitable[dict | None]]]


def _s256_verify(code_verifier: str, code_challenge: str) -> bool:
    """Verify PKCE S256: base64url(sha256(code_verifier)) == code_challenge."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, code_challenge)


def _prune_expired(store: dict[str, dict[str, Any]], ttl: float) -> None:
    """Remove entries older than *ttl* seconds."""
    now = time.monotonic()
    expired = [k for k, v in store.items() if now - v["created_at"] > ttl]
    for k in expired:
        del store[k]


def _base_url(request: Request) -> str:
    """Derive the public base URL from the request."""
    return str(request.base_url).rstrip("/")


async def _authorize_get(request: Request) -> HTMLResponse | JSONResponse:
    """GET /authorize -- render the credential form."""
    state = request.app.state
    params = request.query_params
    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    req_state = params.get("state")
    code_challenge = params.get("code_challenge")
    code_challenge_method = params.get("code_challenge_method", "S256")

    if not all([client_id, redirect_uri, req_state, code_challenge]):
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing required parameters"},
            status_code=400,
        )

    nonce = secrets.token_urlsafe(32)
    state.pending_sessions[nonce] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": req_state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "created_at": time.monotonic(),
    }
    _prune_expired(state.pending_sessions, _SESSION_TTL_S)

    base = _base_url(request)
    submit_url = f"{base}/authorize?nonce={nonce}"
    if state.custom_credential_form_html:
        html = state.custom_credential_form_html(state.relay_schema, submit_url)
    else:
        html = render_credential_form(state.relay_schema, submit_url=submit_url)
    return HTMLResponse(html)


async def _authorize_post(request: Request) -> JSONResponse:
    """POST /authorize -- receive credentials, save, return redirect URL with auth code."""
    state = request.app.state
    nonce = request.query_params.get("nonce")
    if not nonce or nonce not in state.pending_sessions:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Invalid or expired nonce"},
            status_code=400,
        )

    session = state.pending_sessions.pop(nonce)
    if time.monotonic() - session["created_at"] > _SESSION_TTL_S:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Session expired"},
            status_code=400,
        )

    try:
        credentials = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Invalid JSON body"},
            status_code=400,
        )

    next_step = None
    if state.on_credentials_saved:
        try:
            res = state.on_credentials_saved(credentials)
            if inspect.iscoroutine(res):
                res = await res
            if isinstance(res, dict):
                next_step = res
        except Exception:
            logger.exception("on_credentials_saved failed")
            return JSONResponse(
                {"error": "server_error", "error_description": "Failed to save credentials"},
                status_code=500,
            )

    auth_code = secrets.token_urlsafe(32)
    state.auth_codes[auth_code] = {
        "code_challenge": session["code_challenge"],
        "code_challenge_method": session["code_challenge_method"],
        "created_at": time.monotonic(),
    }
    _prune_expired(state.auth_codes, _AUTH_CODE_TTL_S)

    redirect_uri = session["redirect_uri"]
    req_state = session["state"]
    sep = "&" if "?" in redirect_uri else "?"
    redirect_url = f"{redirect_uri}{sep}code={auth_code}&state={req_state}"

    response_body = {"ok": True, "redirect_url": redirect_url}
    if next_step:
        response_body["next_step"] = next_step
        if next_step.get("type") in ("otp_required", "password_required"):
            state.pending_step.update(
                {"active": True, "created_at": time.monotonic(), "attempts": 0}
            )

    return JSONResponse(response_body)


async def _authorize(request: Request) -> HTMLResponse | JSONResponse:
    if request.method == "GET":
        return await _authorize_get(request)
    return await _authorize_post(request)


async def _token(request: Request) -> JSONResponse:
    state = request.app.state
    try:
        form = await request.form()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    if form.get("grant_type") != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    code = str(form.get("code", ""))
    verifier = str(form.get("code_verifier", ""))
    if not code or not verifier:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing code or code_verifier"},
            status_code=400,
        )

    entry = state.auth_codes.pop(code, None)
    if entry is None or (time.monotonic() - entry["created_at"] > _AUTH_CODE_TTL_S):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    if entry["code_challenge_method"] != "S256" or not _s256_verify(
        verifier, entry["code_challenge"]
    ):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    access_token = state.jwt_issuer.issue_access_token(sub="local-user")
    return JSONResponse({"access_token": access_token, "token_type": "Bearer", "expires_in": 3600})


async def _otp_handler(request: Request) -> JSONResponse:
    state = request.app.state
    if not state.pending_step.get("active"):
        return JSONResponse(
            {"error": "invalid_request", "error_description": "No active step session"},
            status_code=400,
        )

    if time.monotonic() - state.pending_step.get("created_at", 0.0) > _OTP_TIMEOUT_S:
        state.pending_step.clear()
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Step session expired"},
            status_code=400,
        )

    try:
        step_data = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Invalid JSON body"},
            status_code=400,
        )

    state.pending_step["attempts"] = state.pending_step.get("attempts", 0) + 1
    if state.pending_step["attempts"] > _OTP_MAX_ATTEMPTS:
        state.pending_step.clear()
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Too many attempts"},
            status_code=400,
        )

    next_step = None
    if state.on_step_submitted:
        try:
            res = state.on_step_submitted(step_data)
            if inspect.iscoroutine(res):
                res = await res
            if isinstance(res, dict):
                next_step = res
        except Exception:
            logger.exception("on_step_submitted failed")
            return JSONResponse(
                {"error": "server_error", "error_description": "Failed to process step input"},
                status_code=500,
            )

    if next_step and next_step.get("type") == "error":
        return JSONResponse({"ok": False, "error": next_step.get("text", "Invalid input")})

    if next_step and next_step.get("type") in ("otp_required", "password_required"):
        state.pending_step.update({"active": True, "created_at": time.monotonic(), "attempts": 0})
        return JSONResponse({"ok": True, "next_step": next_step})

    state.pending_step.clear()
    return JSONResponse({"ok": True})


def create_local_oauth_app(
    *,
    server_name: str,
    relay_schema: dict[str, Any],
    on_credentials_saved: CredentialsCallback | None = None,
    on_step_submitted: StepCallback | None = None,
    jwt_issuer: JWTIssuer | None = None,
    custom_credential_form_html: Callable[[dict[str, Any], str], str] | None = None,
) -> tuple[Starlette, JWTIssuer]:
    """Create OAuth 2.1 Authorization Server Starlette app."""
    if jwt_issuer is None:
        jwt_issuer = JWTIssuer(server_name=server_name)

    app = Starlette(
        routes=[
            Route("/authorize", _authorize, methods=["GET", "POST"]),
            Route("/otp", _otp_handler, methods=["POST"]),
            Route("/token", _token, methods=["POST"]),
            Route(
                "/setup-status",
                lambda r: JSONResponse(r.app.state.setup_status),
                methods=["GET"],
            ),
            Route(
                "/.well-known/oauth-authorization-server",
                lambda r: JSONResponse(authorization_server_metadata(_base_url(r))),
                methods=["GET"],
            ),
            Route(
                "/.well-known/oauth-protected-resource",
                lambda r: JSONResponse(
                    protected_resource_metadata(resource=_base_url(r), authorization_servers=[_base_url(r)])
                ),
                methods=["GET"],
            ),
        ]
    )

    app.state.pending_sessions = {}
    app.state.auth_codes = {}
    app.state.pending_step = {}
    app.state.setup_status = {"gdrive": "idle"}
    app.state.relay_schema = relay_schema
    app.state.custom_credential_form_html = custom_credential_form_html
    app.state.on_credentials_saved = on_credentials_saved
    app.state.on_step_submitted = on_step_submitted
    app.state.jwt_issuer = jwt_issuer

    def mark_setup_complete(key: str = "gdrive") -> None:
        app.state.setup_status[key] = "complete"

    app.state.mark_setup_complete = mark_setup_complete  # type: ignore[attr-defined]
    return app, jwt_issuer
