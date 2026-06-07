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
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from mcp_core.auth.credential_form import is_oauth_field, is_secret_field, render_credential_form
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
# on_credentials_saved receives the submitted credentials AND a
# per-authorize-session SubjectContext ({"sub": "<uuid>"}). The sub is
# generated fresh when GET /authorize renders the form, threaded through POST
# /authorize, and stamped onto the JWT issued at /token — so consumers that
# persist credentials keyed by sub (remote-relay multi-user mode) can
# later look them up via AsyncLocalStorage in the Bearer auth scope. Without
# this primitive every browser session collapsed to a static local-user
# subject and leaked credentials across users.
SubjectContext = dict[str, str]
CredentialsCallback = Callable[
    [dict[str, str], SubjectContext], Union[dict[str, Any] | None, Awaitable[dict[str, Any] | None]]
]
# on_step_submitted also receives the SubjectContext carried through
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


class _LocalOAuthServer:
    def __init__(
        self,
        *,
        server_name: str,
        relay_schema: dict[str, Any],
        on_credentials_saved: CredentialsCallback | None = None,
        on_step_submitted: StepCallback | None = None,
        jwt_issuer: JWTIssuer | None = None,
        custom_credential_form_html: Callable[..., str] | None = None,
    ):
        self.server_name = server_name
        self.relay_schema = relay_schema
        self.on_credentials_saved = on_credentials_saved
        self.on_step_submitted = on_step_submitted
        self.custom_credential_form_html = custom_credential_form_html

        if jwt_issuer is None:
            jwt_issuer = JWTIssuer(server_name=server_name)
        self.jwt_issuer = jwt_issuer

        # In-memory stores keyed by nonce / auth_code.
        self.pending_sessions: dict[str, dict[str, Any]] = {}
        self.auth_codes: dict[str, dict[str, Any]] = {}
        self.pending_prefills: dict[str, dict[str, Any]] = {}
        self._PREFILL_TTL_S = 300.0

        self._relay_password = os.environ.get("MCP_RELAY_PASSWORD", "")
        configure_relay_login(self._relay_password)

        self._pending_step: dict[str, Any] = {}
        self._setup_status: dict[str, str] = {"gdrive": "idle"}

    def _mark_pending_step(self, sub: str) -> None:
        """Activate the pending step session keyed by the authorize subject."""
        self._pending_step["active"] = True
        self._pending_step["created_at"] = time.monotonic()
        self._pending_step["attempts"] = 0
        self._pending_step["sub"] = sub

    def _clear_pending_step(self) -> None:
        """Xóa pending step session (sau khi complete hoặc expired)."""
        self._pending_step.clear()

    def _prune_expired(self, store: dict[str, dict[str, Any]], ttl: float) -> None:
        """Remove entries older than *ttl* seconds."""
        now = time.monotonic()
        expired = [k for k, v in store.items() if now - v["created_at"] > ttl]
        for k in expired:
            del store[k]

    def _issue_token_response(self, sub: str) -> JSONResponse:
        """Build the standard /token success body for *sub*."""
        access_token = self.jwt_issuer.issue_access_token(sub=sub)
        refresh_token = self.jwt_issuer.issue_refresh_token(sub=sub)
        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": refresh_token,
                "scope": "offline_access",
            }
        )

    def _handle_refresh_token(self, form: Any) -> JSONResponse:
        """Handle grant_type=refresh_token (RFC 6749 §6) statelessly."""
        refresh_token = form.get("refresh_token")
        if not refresh_token:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Missing refresh_token"},
                status_code=400,
            )
        try:
            claims = self.jwt_issuer.verify_refresh_token(str(refresh_token))
        except Exception:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        return self._issue_token_response(str(claims["sub"]))

    def mark_setup_complete(self, key: str = "gdrive") -> None:
        self._setup_status[key] = "complete"

    def mark_setup_failed(self, key: str = "gdrive", error: str = "unknown error") -> None:
        message = " ".join(str(error).split()) or "unknown error"
        self._setup_status[key] = f"error:{message}"

    async def authorize_get(self, request: Request) -> HTMLResponse | JSONResponse:
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

        prefill: dict[str, str] = {}
        self._prune_expired(self.pending_prefills, self._PREFILL_TTL_S)
        stored = self.pending_prefills.pop(state, None) if state else None
        if stored:
            prefill.update(stored.get("data", {}))
        else:
            for k in params.keys():
                if k.startswith("prefill_"):
                    prefill[k.removeprefix("prefill_")] = params[k]

        nonce = secrets.token_urlsafe(32)
        sub = secrets.token_urlsafe(16)
        self.pending_sessions[nonce] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "created_at": time.monotonic(),
            "sub": sub,
        }

        self._prune_expired(self.pending_sessions, _SESSION_TTL_S)

        base = derive_base_url(request)
        submit_url = f"{base}/authorize?nonce={nonce}"
        if self.custom_credential_form_html is not None:
            html_content = self.custom_credential_form_html(self.relay_schema, submit_url, prefill=prefill)
        else:
            html_content = render_credential_form(self.relay_schema, submit_url=submit_url, prefill=prefill)
        return HTMLResponse(html_content)

    async def authorize_post(self, request: Request) -> JSONResponse:
        """POST /authorize -- receive credentials, save, return redirect URL with auth code."""
        nonce = request.query_params.get("nonce")
        if not nonce or nonce not in self.pending_sessions:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid or expired nonce"},
                status_code=400,
            )

        session = self.pending_sessions.pop(nonce)

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

        for _k in list(self._setup_status.keys()):
            self._setup_status[_k] = "idle"

        context: SubjectContext = {"sub": session["sub"]}
        next_step: dict[str, Any] | None = None
        if self.on_credentials_saved is not None:
            try:
                result = self.on_credentials_saved(credentials, context)
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

        is_multi_step = next_step is not None and next_step.get("type") in (
            "otp_required",
            "password_required",
        )
        if not is_multi_step:
            try:
                _mark_config_setup_complete(self.server_name)
            except Exception:  # noqa: BLE001
                logger.opt(exception=True).warning("Failed to mark _setup_complete=true for {}", self.server_name)

        auth_code = secrets.token_urlsafe(32)
        self.auth_codes[auth_code] = {
            "code_challenge": session["code_challenge"],
            "code_challenge_method": session["code_challenge_method"],
            "created_at": time.monotonic(),
            "sub": session["sub"],
        }

        self._prune_expired(self.auth_codes, _AUTH_CODE_TTL_S)

        redirect_uri = session["redirect_uri"]
        state = session["state"]
        separator = "&" if "?" in redirect_uri else "?"
        redirect_url = f"{redirect_uri}{separator}code={auth_code}&state={state}"

        response_body: dict = {"ok": True, "redirect_url": redirect_url}
        if next_step:
            response_body["next_step"] = next_step
            if next_step.get("type") in ("otp_required", "password_required"):
                self._mark_pending_step(session["sub"])

        return JSONResponse(response_body)

    async def authorize(self, request: Request):
        """Dispatch GET/POST on /authorize."""
        if self._relay_password:
            gated = await require_relay_session(
                dict(request.cookies), str(request.url.path) + (f"?{request.url.query}" if request.url.query else "")
            )
            if gated is not None:
                return gated
        if request.method == "GET":
            return await self.authorize_get(request)
        return await self.authorize_post(request)

    async def authorize_prefill(self, request: Request):
        """POST /authorize/prefill -- driver-only side channel for form prefill."""
        if self._relay_password:
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
        data: dict[str, str] = {}
        for k, v in body.items():
            if v is not None and len(str(v)) > 0:
                data[str(k)] = str(v)
        self.pending_prefills[state] = {"data": data, "created_at": time.monotonic()}
        self._prune_expired(self.pending_prefills, self._PREFILL_TTL_S)
        return JSONResponse({}, status_code=204)

    async def token(self, request: Request) -> JSONResponse:
        """POST /token -- authorization_code exchange or refresh_token rotation."""
        try:
            form = await request.form()
        except Exception:
            return JSONResponse({"error": "invalid_request"}, status_code=400)

        grant_type = form.get("grant_type")
        if grant_type == "refresh_token":
            return self._handle_refresh_token(form)
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

        entry = self.auth_codes.pop(code, None)
        if entry is None:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        if time.monotonic() - entry["created_at"] > _AUTH_CODE_TTL_S:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        method = entry["code_challenge_method"]
        if method != "S256":
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Only S256 is supported"},
                status_code=400,
            )

        if not _s256_verify(code_verifier, entry["code_challenge"]):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        return self._issue_token_response(entry["sub"])

    async def otp_handler(self, request: Request) -> JSONResponse:
        """POST /otp -- receive multi-step auth input (OTP code or 2FA password)."""
        if not self._pending_step.get("active"):
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "No active step session",
                },
                status_code=400,
            )

        created_at = self._pending_step.get("created_at", 0.0)
        if time.monotonic() - created_at > _OTP_TIMEOUT_S:
            self._clear_pending_step()
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "Step session expired",
                },
                status_code=400,
            )

        try:
            step_data: dict[str, str] = await request.json()
        except Exception:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid JSON body"},
                status_code=400,
            )

        self._pending_step["attempts"] = self._pending_step.get("attempts", 0) + 1

        if self._pending_step["attempts"] > _OTP_MAX_ATTEMPTS:
            self._clear_pending_step()
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "Too many attempts",
                },
                status_code=400,
            )

        context: SubjectContext = {"sub": self._pending_step["sub"]}
        next_step: dict[str, Any] | None = None
        if self.on_step_submitted is not None:
            try:
                result = self.on_step_submitted(step_data, context)
                if inspect.isawaitable(result):
                    result = await result
                if isinstance(result, dict):
                    next_step = cast("dict[str, Any]", result)
            except Exception:
                logger.exception("on_step_submitted callback failed")
                return JSONResponse(
                    {"error": "server_error", "error_description": "Step validation failed"},
                    status_code=500,
                )

        if next_step is None:
            self._clear_pending_step()
            try:
                _mark_config_setup_complete(self.server_name)
            except Exception:  # noqa: BLE001
                logger.opt(exception=True).warning("Failed to mark _setup_complete=true for {}", self.server_name)
            return JSONResponse({"ok": True})

        if next_step.get("type") == "error":
            return JSONResponse(
                {"ok": False, "error": next_step.get("text", "Unknown error")},
            )

        self._pending_step["attempts"] = 0
        self._pending_step["created_at"] = time.monotonic()
        return JSONResponse({"ok": True, "next_step": next_step})

    async def well_known_as(self, request: Request) -> JSONResponse:
        return JSONResponse(authorization_server_metadata(derive_base_url(request)))

    async def well_known_pr(self, request: Request) -> JSONResponse:
        base = derive_base_url(request)
        return JSONResponse(protected_resource_metadata(resource=base, authorization_servers=[base]))

    async def setup_status(self, request: Request) -> JSONResponse:
        return JSONResponse(self._setup_status)

    async def root(self, request: Request):
        """GET / -- auto-generate PKCE and redirect to /authorize."""
        base = derive_base_url(request)
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

    async def callback_done(self, request: Request) -> HTMLResponse:
        """GET /callback-done -- friendly "tab can be closed" page."""
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

    async def register_handler(self, request: Request) -> JSONResponse:
        """RFC 7591 Dynamic Client Registration (echo-style)."""
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

    async def login_get(self, request: Request):
        """GET /login -- render the relay-password form."""
        next_param = request.query_params.get("next", "/authorize")
        return await login_get_handler(next_param)

    async def login_post(self, request: Request):
        """POST /login -- verify the relay password and issue a session cookie."""
        form = await request.form()
        ip = request.client.host if request.client else "unknown"
        return await login_post_handler(dict(form), ip=ip)

    def build_app(self) -> Starlette:
        routes = [
            Route("/", self.root, methods=["GET"]),
            Route("/login", self.login_get, methods=["GET"]),
            Route("/login", self.login_post, methods=["POST"]),
            Route("/authorize", self.authorize, methods=["GET", "POST"]),
            Route("/authorize/prefill", self.authorize_prefill, methods=["POST"]),
            Route("/otp", self.otp_handler, methods=["POST"]),
            Route("/token", self.token, methods=["POST"]),
            Route("/register", self.register_handler, methods=["POST"]),
            Route("/setup-status", self.setup_status, methods=["GET"]),
            Route("/callback-done", self.callback_done, methods=["GET"]),
            Route("/.well-known/oauth-authorization-server", self.well_known_as, methods=["GET"]),
            Route("/.well-known/oauth-protected-resource", self.well_known_pr, methods=["GET"]),
        ]
        app = Starlette(routes=routes)
        app.state.mark_setup_complete = self.mark_setup_complete
        app.state.mark_setup_failed = self.mark_setup_failed
        return app


def create_local_oauth_app(
    *,
    server_name: str,
    relay_schema: dict[str, Any],
    on_credentials_saved: CredentialsCallback | None = None,
    on_step_submitted: StepCallback | None = None,
    jwt_issuer: JWTIssuer | None = None,
    custom_credential_form_html: Callable[..., str] | None = None,
) -> tuple[Starlette, JWTIssuer]:
    """Create OAuth 2.1 Authorization Server Starlette app."""
    server = _LocalOAuthServer(
        server_name=server_name,
        relay_schema=relay_schema,
        on_credentials_saved=on_credentials_saved,
        on_step_submitted=on_step_submitted,
        jwt_issuer=jwt_issuer,
        custom_credential_form_html=custom_credential_form_html,
    )
    return server.build_app(), server.jwt_issuer


# ---------------------------------------------------------------------------
# D7 — Pre-fill renderer + form-submission merger.
# ---------------------------------------------------------------------------

_SECRET_PLACEHOLDER = "••••••••(configured)"


def _field_name(field: dict) -> str:
    """Return the canonical config key for a relay field."""
    return str(field.get("name") or field.get("key") or "")


def render_field(field: dict, current_value: Any) -> str:
    """Render an HTML <label>+<input> for a single relay field."""
    name = _field_name(field)
    label = field.get("label", name)
    field_type = field.get("type", "text")

    if is_oauth_field(field):
        status = "Connected" if current_value else "Not connected"
        return (
            f'<div class="field oauth-field"><label>{_escape(label)}</label> '
            f'<span class="oauth-status">{status}</span> '
            f'<button type="button" class="oauth-reauth" data-field="{_escape(name)}">'
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
    """Merge a form submission into the current config per D7 rules."""
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
