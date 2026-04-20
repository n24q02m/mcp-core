"""Delegated OAuth 2.1 Authorization Server as a Starlette ASGI app.

Unified abstraction for upstream OAuth providers. Fronts two upstream flows
behind a single local OAuth 2.1 PKCE facade for the MCP client:

* ``redirect`` flow -- classic authorization_code redirect (Notion, Grafana,
  GitHub, ...). The local server proxies ``/authorize`` to the upstream
  authorize endpoint, handles the callback, exchanges the upstream code for
  upstream tokens via ``upstream.token_url``, forwards the tokens to the
  consumer via ``on_token_received``, then finishes the local PKCE exchange
  so the MCP client receives a local JWT.
* ``device_code`` flow (RFC 8628) -- used by GDrive, Outlook, etc. The local
  server initiates the upstream device authorization, renders a page showing
  ``user_code`` + ``verification_url``, runs a background polling task on
  ``upstream.token_url`` until the upstream grants a token, invokes
  ``on_token_received``, and signals completion via the setup-status endpoint.

Routes:

- GET  /authorize                                 -- Initiate upstream flow
- GET  /callback                                  -- (redirect flow) upstream redirect
- POST /token                                     -- Exchange local auth code + PKCE verifier for JWT
- GET  /setup-status                              -- Poll background device-code completion
- GET  /.well-known/oauth-authorization-server    -- RFC 8414 metadata
- GET  /.well-known/oauth-protected-resource      -- RFC 9728 metadata

The ``/mcp`` endpoint is NOT included -- it is mounted by the transport layer.

The upstream tokens are passed to ``on_token_received`` ONLY; they are never
persisted by this module. Storage is the consumer's responsibility.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import os
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal, Union

import httpx
from loguru import logger
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from mcp_core.auth.well_known import (
    authorization_server_metadata,
    protected_resource_metadata,
)
from mcp_core.oauth.jwt_issuer import JWTIssuer

# Auth codes and PKCE sessions expire after 10 minutes
_AUTH_CODE_TTL_S = 600
_SESSION_TTL_S = 600

FlowType = Literal["device_code", "redirect"]

TokenEndpointAuthMethod = Literal["client_secret_basic", "client_secret_post"]

TokenCallback = Callable[[dict[str, Any]], Union[None, Awaitable[None]]]


@dataclass
class UpstreamOAuthConfig:
    """Configuration for the upstream OAuth provider.

    Fields required depend on ``flow``:

    * ``redirect``: ``authorize_url`` required.
    * ``device_code``: ``device_auth_url`` required.
    """

    # Common
    token_url: str
    client_id: str
    scopes: list[str] = field(default_factory=list)
    client_secret: str | None = None
    # How to pass client credentials to the upstream token endpoint.
    # Defaults to ``client_secret_basic`` per RFC 6749 §2.3.1. Notion / GitHub
    # / Microsoft require basic; Google / Slack accept both.
    token_endpoint_auth_method: TokenEndpointAuthMethod = "client_secret_basic"
    # Redirect flow only
    authorize_url: str | None = None
    callback_path: str = "/callback"
    # Device code flow only
    device_auth_url: str | None = None
    poll_interval_ms: int = 5000


def _build_client_auth(form_data: dict[str, str], upstream: UpstreamOAuthConfig) -> dict[str, str]:
    """Mutate ``form_data`` with client credentials and return auth headers.

    Public clients (no ``client_secret``) put ``client_id`` in the body and
    no header. Confidential clients default to HTTP Basic per RFC 6749;
    callers can opt into ``client_secret_post`` for providers that require it.
    """
    if upstream.client_secret is None:
        form_data["client_id"] = upstream.client_id
        return {}
    if upstream.token_endpoint_auth_method == "client_secret_post":
        form_data["client_id"] = upstream.client_id
        form_data["client_secret"] = upstream.client_secret
        return {}
    encoded = base64.b64encode(f"{upstream.client_id}:{upstream.client_secret}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}


def _s256_verify(code_verifier: str, code_challenge: str) -> bool:
    """Verify PKCE S256: base64url(sha256(code_verifier)) == code_challenge."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, code_challenge)


def _render_device_code_page(*, server_name: str, user_code: str, verification_url: str) -> str:
    """Render a minimal HTML page showing the device code to the user."""
    safe_name = server_name.replace("<", "&lt;").replace(">", "&gt;")
    safe_code = user_code.replace("<", "&lt;").replace(">", "&gt;")
    safe_url = verification_url.replace('"', "&quot;")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Authorize {safe_name}</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #0d0d0d; color: #eee;
       display: flex; align-items: center; justify-content: center;
       min-height: 100vh; margin: 0; }}
.card {{ background: #181818; padding: 2rem 3rem; border-radius: 12px;
        border: 1px solid #333; max-width: 480px; text-align: center; }}
h1 {{ margin-top: 0; }}
.code {{ font-size: 2rem; font-family: ui-monospace, monospace;
         letter-spacing: 0.25em; padding: 1rem 1.5rem; background: #000;
         border-radius: 8px; border: 1px solid #444; margin: 1.5rem 0; }}
a {{ color: #4ea1ff; }}
.status {{ margin-top: 1.5rem; color: #888; font-size: 0.9rem; }}
</style>
</head>
<body>
<div class="card">
  <h1>Authorize {safe_name}</h1>
  <p>Visit the URL below and enter this code:</p>
  <div class="code">{safe_code}</div>
  <p><a href="{safe_url}" target="_blank" rel="noopener noreferrer">{safe_url}</a></p>
  <p class="status" id="status">Waiting for you to approve...</p>
</div>
<script>
async function poll() {{
  try {{
    const r = await fetch('/setup-status');
    const j = await r.json();
    const s = j[Object.keys(j)[0]] || 'idle';
    if (s === 'complete') {{
      document.getElementById('status').textContent = 'Authorized! You can close this window.';
      return;
    }}
    if (s === 'error') {{
      document.getElementById('status').textContent = 'Authorization failed. Please restart.';
      return;
    }}
  }} catch (e) {{}}
  setTimeout(poll, 2000);
}}
poll();
</script>
</body>
</html>
"""


def create_delegated_oauth_app(
    *,
    server_name: str,
    flow: FlowType,
    upstream: UpstreamOAuthConfig,
    on_token_received: TokenCallback,
    jwt_issuer: JWTIssuer | None = None,
) -> tuple[Starlette, JWTIssuer]:
    """Create a delegated OAuth 2.1 Authorization Server Starlette app.

    Args:
        server_name: Identifier for the MCP server (used for JWT iss/aud and
            for the JWT key directory when no issuer is provided).
        flow: Either ``"device_code"`` or ``"redirect"``.
        upstream: Upstream OAuth provider configuration.
        on_token_received: Callback invoked with the raw upstream token dict
            (``access_token``, optionally ``refresh_token``/``expires_in``/...)
            once the upstream flow completes. Consumer persists tokens as it
            sees fit -- this module never stores them.
        jwt_issuer: Optional pre-created JWTIssuer.

    Returns:
        ``(app, jwt_issuer)``. ``jwt_issuer`` is needed by the transport
        layer to verify Bearer tokens on ``/mcp``.
    """
    if flow == "redirect" and not upstream.authorize_url:
        raise ValueError("authorize_url is required for redirect flow")
    if flow == "device_code" and not upstream.device_auth_url:
        raise ValueError("device_auth_url is required for device_code flow")

    if jwt_issuer is None:
        jwt_issuer = JWTIssuer(server_name=server_name)

    # Structure keyed by upstream-state nonce: PKCE session from the MCP client.
    # {nonce: {client_id, redirect_uri, state, code_challenge, code_challenge_method, created_at}}
    pending_sessions: dict[str, dict[str, Any]] = {}
    # Local auth codes issued to the MCP client after upstream completes.
    # {auth_code: {code_challenge, code_challenge_method, created_at}}
    auth_codes: dict[str, dict[str, Any]] = {}
    # Setup status for device-code polling UI.
    _setup_status: dict[str, str] = {server_name: "idle"}
    # Background poll tasks to cancel on shutdown.
    _poll_tasks: set[asyncio.Task] = set()
    # Device-code flow: latest pending session (single-user). When the upstream
    # approves, we inject auth code so subsequent /token can complete.
    _device_pending: dict[str, Any] = {}

    def _prune_expired(store: dict[str, dict[str, Any]], ttl: float) -> None:
        now = time.monotonic()
        expired = [k for k, v in store.items() if now - v["created_at"] > ttl]
        for k in expired:
            del store[k]

    def _base_url(request: Request) -> str:
        """Derive the public base URL. See ``local_oauth_app._base_url`` for
        the resolution order; this function is the delegated-flow twin and
        must stay in lock-step so both well-known documents agree on the
        issuer.
        """
        public_url = os.environ.get("PUBLIC_URL")
        if public_url:
            return public_url.rstrip("/")
        return str(request.base_url).rstrip("/")

    def mark_setup_complete(key: str | None = None) -> None:
        k = key or server_name
        _setup_status[k] = "complete"

    def _mark_setup_error(key: str | None = None) -> None:
        k = key or server_name
        _setup_status[k] = "error"

    async def _invoke_token_callback(tokens: dict[str, Any]) -> None:
        try:
            result = on_token_received(tokens)
            if inspect.isawaitable(result):
                await result
        except Exception:  # noqa: BLE001
            logger.exception("on_token_received callback failed")
            raise

    # ------------------------------------------------------------------
    # Redirect flow
    # ------------------------------------------------------------------

    async def _authorize_redirect(request: Request) -> JSONResponse | RedirectResponse:
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
        upstream_redirect = f"{base}{upstream.callback_path}"
        qs: dict[str, str] = {
            "client_id": upstream.client_id,
            "redirect_uri": upstream_redirect,
            "response_type": "code",
            "state": nonce,
        }
        if upstream.scopes:
            qs["scope"] = " ".join(upstream.scopes)

        assert upstream.authorize_url is not None
        separator = "&" if "?" in upstream.authorize_url else "?"
        from urllib.parse import urlencode

        target = f"{upstream.authorize_url}{separator}{urlencode(qs)}"
        return RedirectResponse(target, status_code=302)

    async def _callback(request: Request) -> JSONResponse | RedirectResponse:
        params = request.query_params
        code = params.get("code")
        state = params.get("state")

        if not code or not state:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Missing code or state"},
                status_code=400,
            )

        session = pending_sessions.pop(state, None)
        if session is None:
            # CSRF: unknown state.
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid state"},
                status_code=400,
            )

        if time.monotonic() - session["created_at"] > _SESSION_TTL_S:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Session expired"},
                status_code=400,
            )

        base = _base_url(request)
        form_data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": f"{base}{upstream.callback_path}",
        }
        auth_headers = _build_client_auth(form_data, upstream)

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    upstream.token_url,
                    data=form_data,
                    headers={"Accept": "application/json", **auth_headers},
                )
        except Exception:  # noqa: BLE001
            logger.exception("Upstream token exchange failed")
            return JSONResponse(
                {"error": "server_error", "error_description": "Upstream token exchange failed"},
                status_code=502,
            )

        if resp.status_code != 200:
            return JSONResponse(
                {
                    "error": "invalid_grant",
                    "error_description": f"Upstream rejected token exchange: {resp.text}",
                },
                status_code=400,
            )

        tokens = resp.json()

        try:
            await _invoke_token_callback(tokens)
        except Exception:
            return JSONResponse(
                {"error": "server_error", "error_description": "Failed to persist tokens"},
                status_code=500,
            )

        auth_code = secrets.token_urlsafe(32)
        auth_codes[auth_code] = {
            "code_challenge": session["code_challenge"],
            "code_challenge_method": session["code_challenge_method"],
            "created_at": time.monotonic(),
        }
        _prune_expired(auth_codes, _AUTH_CODE_TTL_S)

        redirect_uri = session["redirect_uri"]
        separator = "&" if "?" in redirect_uri else "?"
        redirect_url = f"{redirect_uri}{separator}code={auth_code}&state={session['state']}"
        return RedirectResponse(redirect_url, status_code=302)

    # ------------------------------------------------------------------
    # Device code flow
    # ------------------------------------------------------------------

    async def _poll_device_token(
        *,
        device_code: str,
        interval_ms: int,
        auth_code: str,
    ) -> None:
        """Background task: poll upstream token endpoint until granted or error.

        Implements the RFC 8628 polling semantics: ``authorization_pending``
        -> continue; ``slow_down`` -> increase interval; terminal errors stop.
        """
        interval = max(interval_ms, 1000) / 1000.0
        form_data: dict[str, str] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
        }
        auth_headers = _build_client_auth(form_data, upstream)

        try:
            async with httpx.AsyncClient() as client:
                while True:
                    await asyncio.sleep(interval)
                    try:
                        resp = await client.post(
                            upstream.token_url,
                            data=form_data,
                            headers={"Accept": "application/json", **auth_headers},
                        )
                    except Exception:  # noqa: BLE001
                        logger.exception("Upstream poll request failed")
                        _mark_setup_error()
                        return

                    if resp.status_code == 200:
                        tokens = resp.json()
                        try:
                            await _invoke_token_callback(tokens)
                        except Exception:
                            _mark_setup_error()
                            return
                        # Stash the auth code so the later /token exchange works.
                        _device_pending["auth_code"] = auth_code
                        mark_setup_complete()
                        return

                    try:
                        body = resp.json()
                    except Exception:  # noqa: BLE001
                        _mark_setup_error()
                        return

                    err = body.get("error")
                    if err == "authorization_pending":
                        continue
                    if err == "slow_down":
                        interval += 5
                        continue
                    # Terminal: access_denied, expired_token, other.
                    logger.warning("Device code polling terminated: {}", err)
                    _mark_setup_error()
                    return
        except asyncio.CancelledError:
            raise

    async def _authorize_device_code(request: Request) -> HTMLResponse | JSONResponse:
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

        # Start upstream device authorization.
        device_form: dict[str, str] = {"client_id": upstream.client_id}
        if upstream.scopes:
            device_form["scope"] = " ".join(upstream.scopes)

        try:
            assert upstream.device_auth_url is not None
            async with httpx.AsyncClient() as client:
                resp = await client.post(upstream.device_auth_url, data=device_form)
        except Exception:  # noqa: BLE001
            logger.exception("Upstream device_auth request failed")
            return JSONResponse(
                {"error": "server_error", "error_description": "Upstream device auth failed"},
                status_code=502,
            )

        if resp.status_code != 200:
            return JSONResponse(
                {
                    "error": "server_error",
                    "error_description": f"Upstream device auth rejected: {resp.text}",
                },
                status_code=502,
            )

        device = resp.json()
        device_code = device.get("device_code")
        user_code = device.get("user_code")
        verification_url = device.get("verification_url") or device.get("verification_uri")
        interval_secs = int(device.get("interval", upstream.poll_interval_ms / 1000))
        if not device_code or not user_code or not verification_url:
            return JSONResponse(
                {
                    "error": "server_error",
                    "error_description": "Upstream device auth response missing fields",
                },
                status_code=502,
            )

        # Pre-allocate the auth code now so the /token exchange can use it
        # as soon as polling completes (no race with the browser redirect).
        auth_code = secrets.token_urlsafe(32)
        auth_codes[auth_code] = {
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "created_at": time.monotonic(),
        }
        _prune_expired(auth_codes, _AUTH_CODE_TTL_S)

        # Reset setup status and spawn background polling task.
        _setup_status[server_name] = "pending"
        _device_pending["redirect_uri"] = redirect_uri
        _device_pending["state"] = state
        _device_pending["auth_code"] = auth_code

        task = asyncio.create_task(
            _poll_device_token(
                device_code=device_code,
                interval_ms=interval_secs * 1000,
                auth_code=auth_code,
            )
        )
        _poll_tasks.add(task)
        task.add_done_callback(_poll_tasks.discard)

        html = _render_device_code_page(
            server_name=server_name,
            user_code=user_code,
            verification_url=verification_url,
        )
        return HTMLResponse(html)

    # ------------------------------------------------------------------
    # Shared endpoints
    # ------------------------------------------------------------------

    async def authorize(request: Request) -> HTMLResponse | JSONResponse | RedirectResponse:
        if flow == "redirect":
            return await _authorize_redirect(request)
        return await _authorize_device_code(request)

    async def token(request: Request) -> JSONResponse:
        try:
            form = await request.form()
        except Exception:  # noqa: BLE001
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

        entry = auth_codes.pop(code, None)
        if entry is None:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        if time.monotonic() - entry["created_at"] > _AUTH_CODE_TTL_S:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        if entry["code_challenge_method"] != "S256":
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Only S256 is supported"},
                status_code=400,
            )

        if not _s256_verify(code_verifier, entry["code_challenge"]):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        access_token = jwt_issuer.issue_access_token(sub="local-user")
        return JSONResponse({"access_token": access_token, "token_type": "Bearer", "expires_in": 3600})

    async def setup_status(_request: Request) -> JSONResponse:
        return JSONResponse(_setup_status)

    async def well_known_as(request: Request) -> JSONResponse:
        return JSONResponse(authorization_server_metadata(_base_url(request)))

    async def well_known_pr(request: Request) -> JSONResponse:
        base = _base_url(request)
        return JSONResponse(protected_resource_metadata(resource=base, authorization_servers=[base]))

    async def root(request: Request) -> RedirectResponse:
        """GET / -- auto-generate PKCE and redirect to /authorize.

        Parity with ``create_local_oauth_app``'s ``root`` handler. Users
        arriving at the bare server URL (bookmark, log line) get a usable
        OAuth flow without constructing PKCE params manually. Delegated
        ``/authorize`` validates these against its upstream configuration,
        so ``local-browser`` as ``client_id`` works for both redirect and
        device-code flows.
        """
        base = _base_url(request)
        _code_verifier = secrets.token_urlsafe(64)
        _challenge_digest = hashlib.sha256(_code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(_challenge_digest).rstrip(b"=").decode("ascii")
        state = secrets.token_urlsafe(16)
        from urllib.parse import urlencode

        params = urlencode(
            {
                "client_id": "local-browser",
                "redirect_uri": f"{base}/callback-done",
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return RedirectResponse(url=f"/authorize?{params}", status_code=302)

    async def callback_done(_request: Request) -> HTMLResponse:
        """GET /callback-done -- terminal "tab can be closed" landing page."""
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

    routes = [
        Route("/", root, methods=["GET"]),
        Route("/callback-done", callback_done, methods=["GET"]),
        Route("/authorize", authorize, methods=["GET"]),
        Route("/token", token, methods=["POST"]),
        Route("/setup-status", setup_status, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", well_known_as, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", well_known_pr, methods=["GET"]),
    ]
    if flow == "redirect":
        routes.append(Route(upstream.callback_path, _callback, methods=["GET"]))

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _lifespan(_app: Starlette):
        try:
            yield
        finally:
            for task in list(_poll_tasks):
                task.cancel()
            for task in list(_poll_tasks):
                try:
                    await task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass

    app = Starlette(routes=routes, lifespan=_lifespan)
    app.state.mark_setup_complete = mark_setup_complete  # type: ignore[attr-defined]

    return app, jwt_issuer
