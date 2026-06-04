"""Local MCP server with self-hosted OAuth 2.1 AS.

Entry point for credential servers running in local mode (single-user,
127.0.0.1). Combines:
1. OAuth 2.1 AS (credential form + token exchange) -- serves /authorize, /token, /.well-known/*
2. MCP Streamable HTTP transport -- serves /mcp with Bearer auth
3. Lifecycle lock -- prevents two instances on same port
4. Auto-open browser -- opens /authorize on first run when no credentials exist
"""

from __future__ import annotations

import os
import socket
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Union

from loguru import logger

from starlette.datastructures import Headers

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from starlette.applications import Starlette
    from starlette.types import ASGIApp, Receive, Scope, Send

    from mcp_core.oauth.jwt_issuer import JWTIssuer


# Callback may be sync or async. Async lets callbacks perform I/O without
# complex event loop management. See mcp_core.auth.local_oauth_app for details.
#
# Credential callback now receives a second arg ``context`` (``SubjectContext``)
# carrying the per-authorize-request ``sub``. Consumers that want multi-user
# isolation (remote-relay public URLs) key their credential store by
# ``context["sub"]``; single-user consumers can simply ignore the arg.
_CredentialsCallback = Callable[[dict[str, str], dict[str, str]], Union[dict | None, Awaitable[dict | None]]]
_StepCallback = Callable[[dict[str, str]], Union[dict | None, Awaitable[dict | None]]]
# Legacy alias retained for existing annotations in this module.
_Callback = _CredentialsCallback

# Middleware invoked after JWT verification. Receives the decoded claims dict
# and a ``next`` coroutine that forwards to the MCP transport.
AuthScope = Callable[[dict[str, Any], Callable[[], Awaitable[None]]], Awaitable[None]]


def find_free_port() -> int:
    """Find an available TCP port on 127.0.0.1.

    Binds to port 0 so the OS assigns an ephemeral port, then immediately
    closes the socket. The returned port is not reserved, but on a
    non-contended dev machine it will be available for immediate use.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]
    except OSError as e:
        raise RuntimeError(f"Could not find a free port: {e}") from e


class BearerMCPApp:
    """ASGI wrapper that enforces Bearer JWT auth before forwarding to the MCP app.

    This is a thin ASGI-level guard that extracts the ``Authorization: Bearer``
    header, verifies the JWT via ``jwt_issuer.verify_access_token()``, and
    either forwards to the inner MCP ASGI app or responds with 401.

    Unlike ``OAuthMiddleware`` (which is a Starlette ``BaseHTTPMiddleware``
    applied to the whole app), this wrapper is route-scoped: it is used as
    the endpoint for the ``/mcp`` route only, so OAuth discovery endpoints
    remain publicly accessible.
    """

    def __init__(
        self,
        inner: ASGIApp,
        jwt_issuer: JWTIssuer,
        auth_scope: AuthScope | None = None,
        *,
        auth_disabled: bool = False,
    ) -> None:
        self._inner = inner
        self._jwt_issuer = jwt_issuer
        self._auth_scope = auth_scope
        self._auth_disabled = auth_disabled
        if auth_disabled:
            logger.warning(
                "BearerMCPApp auth_disabled=True -- Bearer token validation skipped. "
                "Caller must enforce authentication at the network boundary "
                "(e.g. reverse proxy, API gateway)."
            )

    def _resource_metadata_url(self, scope: Scope) -> str:
        """Derive the RFC 9728 protected-resource-metadata URL from the request.

        Mirrors ``well_known.derive_base_url``'s PUBLIC_URL-first convention:
        the deployed servers (oci-vm-prod behind CF Tunnel -> Caddy) set
        ``PUBLIC_URL`` so the advertised metadata URL is the public HTTPS host
        rather than the internal HTTP socket address. When unset, fall back to
        the request Host + ``X-Forwarded-Proto`` (or the raw socket scheme).
        """
        public_url = os.environ.get("PUBLIC_URL")
        if public_url:
            base = public_url.rstrip("/")
        else:
            headers = Headers(scope=scope)
            host = headers.get("host") or "localhost"
            proto = headers.get("x-forwarded-proto") or scope.get("scheme", "http")
            base = f"{proto}://{host}"
        return f"{base}/.well-known/oauth-protected-resource"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._inner(scope, receive, send)
            return

        # Bypass JWT validation when behind external auth boundary (gateway).
        if self._auth_disabled:
            anonymous_claims: dict[str, Any] = {"sub": "anonymous", "anonymous": True}
            if self._auth_scope is not None:

                async def _next() -> None:
                    await self._inner(scope, receive, send)

                await self._auth_scope(anonymous_claims, _next)
                return
            await self._inner(scope, receive, send)
            return

        # Extract Bearer token from headers
        headers = Headers(scope=scope)
        auth_header = headers.get("authorization")
        bearer: str | None = None
        if auth_header:
            scheme, _, token_part = auth_header.partition(" ")
            if scheme.lower() == "bearer" and token_part.strip():
                bearer = token_part.strip()

        if not bearer:
            from starlette.responses import Response

            resp = Response(
                status_code=401,
                headers={"WWW-Authenticate": f'Bearer resource_metadata="{self._resource_metadata_url(scope)}"'},
            )
            await resp(scope, receive, send)
            return

        try:
            claims = self._jwt_issuer.verify_access_token(bearer)
        except Exception:
            from starlette.responses import Response

            resp = Response(
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer resource_metadata="{self._resource_metadata_url(scope)}", error="invalid_token"'
                    )
                },
            )
            await resp(scope, receive, send)
            return

        if self._auth_scope is not None:

            async def _next() -> None:
                await self._inner(scope, receive, send)

            await self._auth_scope(claims, _next)
            return

        await self._inner(scope, receive, send)


def build_local_app(
    mcp: FastMCP,
    *,
    server_name: str,
    relay_schema: dict[str, Any] | None = None,
    on_credentials_saved: _Callback | None = None,
    on_step_submitted: _Callback | None = None,
    jwt_keys_dir: Path | None = None,
    custom_credential_form_html: Callable[..., str] | None = None,
    delegated_oauth: dict[str, Any] | None = None,
    auth_scope: AuthScope | None = None,
    auth_disabled: bool = False,
) -> tuple[Starlette, JWTIssuer]:
    """Construct a combined Starlette app with OAuth AS + MCP transport.

    This is the testable construction seam. It builds the app without
    binding a port or running uvicorn.

    Args:
        mcp: FastMCP server instance.
        server_name: Identifier used for JWT iss/aud and credential storage.
        relay_schema: RelayConfigSchema dict describing the credential form.
            Mutually exclusive with ``delegated_oauth``.
        on_credentials_saved: Optional callback invoked when user submits creds.
            Only used in relay (non-delegated) mode.
        on_step_submitted: Optional callback invoked when user submits a
            multi-step credential (OTP / 2FA password) via ``POST /otp``.
            Receives the step input dict (e.g. ``{"otp_code": "12345"}``)
            and returns the same result shape as ``on_credentials_saved``:
            ``None`` (complete), an error dict, or another step-required dict.
            Only used in relay (non-delegated) mode.
        jwt_keys_dir: Directory for JWT key storage. Defaults to JWTIssuer's default.
        custom_credential_form_html: Optional ``(schema, submit_url) -> html``
            renderer used in place of the default credential form on GET
            /authorize. Passed through to ``create_local_oauth_app``.
            Only used in relay (non-delegated) mode.
        delegated_oauth: Dict configuring upstream OAuth delegation. Mutually
            exclusive with ``relay_schema``. Expected keys:
            ``flow`` (``"redirect"`` or ``"device_code"``),
            ``upstream`` (dict with ``token_url``, ``client_id``, optionally
            ``client_secret``, ``scopes``, ``authorize_url``, ``callback_path``,
            ``device_auth_url``, ``poll_interval_ms``),
            ``on_token_received`` (callback invoked with upstream token dict).
        auth_scope: Optional middleware invoked after JWT verification and
            before the MCP transport handles the request. Receives the decoded
            claims dict and a ``next`` coroutine. Consumers use this to wrap
            the request in a context var (e.g., for per-user token lookup).

    Returns:
        ``(app, jwt_issuer)`` tuple.
    """
    from contextlib import asynccontextmanager
    from typing import cast

    from mcp.server.fastmcp.server import StreamableHTTPASGIApp
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Route

    from mcp_core.oauth.jwt_issuer import JWTIssuer

    if relay_schema is not None and delegated_oauth is not None:
        raise ValueError("`relay_schema` and `delegated_oauth` are mutually exclusive")
    if relay_schema is None and delegated_oauth is None:
        raise ValueError("exactly one of `relay_schema` or `delegated_oauth` must be provided")

    # Build JWT issuer with optional custom keys directory
    jwt_issuer_kwargs: dict[str, Any] = {"server_name": server_name}
    if jwt_keys_dir is not None:
        jwt_issuer_kwargs["keys_dir"] = jwt_keys_dir
    jwt_issuer = JWTIssuer(**jwt_issuer_kwargs)

    if delegated_oauth is not None:
        from mcp_core.auth.delegated_oauth_app import (
            UpstreamOAuthConfig,
            create_delegated_oauth_app,
        )

        upstream_cfg = delegated_oauth["upstream"]
        upstream = UpstreamOAuthConfig(
            token_url=upstream_cfg["token_url"],
            client_id=upstream_cfg["client_id"],
            client_secret=upstream_cfg.get("client_secret"),
            scopes=list(upstream_cfg.get("scopes", [])),
            authorize_url=upstream_cfg.get("authorize_url"),
            callback_path=upstream_cfg.get("callback_path", "/callback"),
            device_auth_url=upstream_cfg.get("device_auth_url"),
            poll_interval_ms=upstream_cfg.get("poll_interval_ms", 5000),
        )
        oauth_app, _ = create_delegated_oauth_app(
            server_name=server_name,
            flow=delegated_oauth["flow"],
            upstream=upstream,
            on_token_received=delegated_oauth["on_token_received"],
            jwt_issuer=jwt_issuer,
        )
    else:
        from mcp_core.auth.local_oauth_app import create_local_oauth_app

        assert relay_schema is not None  # guaranteed by validation above
        oauth_app, _ = create_local_oauth_app(
            server_name=server_name,
            relay_schema=relay_schema,
            on_credentials_saved=on_credentials_saved,
            on_step_submitted=on_step_submitted,
            jwt_issuer=jwt_issuer,
            custom_credential_form_html=custom_credential_form_html,
        )

    # Create MCP ASGI handler via StreamableHTTPSessionManager
    session_manager = StreamableHTTPSessionManager(
        app=cast(Any, mcp)._mcp_server,
    )
    mcp_asgi_handler = StreamableHTTPASGIApp(session_manager)

    # Wrap with Bearer auth (bypass if auth_disabled=True).
    bearer_mcp_app = BearerMCPApp(
        inner=mcp_asgi_handler,
        jwt_issuer=jwt_issuer,
        auth_scope=auth_scope,
        auth_disabled=auth_disabled,
    )

    # Combine OAuth routes + /mcp route into a single Starlette app
    # Reuse the OAuth app's routes and add our /mcp endpoint
    combined_routes = list(oauth_app.routes) + [
        Route("/mcp", endpoint=bearer_mcp_app),
    ]

    @asynccontextmanager
    async def lifespan(app: Starlette):
        async with session_manager.run():
            yield

    combined_app = Starlette(routes=combined_routes, lifespan=lifespan)

    # Forward mark_setup_complete / mark_setup_failed from OAuth app to combined app.
    # Both are used by transport/local_server to wire the ``setup_complete_hook``
    # so consumers (e.g. wet-mcp GDrive device code poll) can signal success
    # AND propagate upstream errors to the browser form.
    mark_fn = getattr(oauth_app.state, "mark_setup_complete", None)
    if mark_fn:
        combined_app.state.mark_setup_complete = mark_fn  # type: ignore[attr-defined]
    mark_failed_fn = getattr(oauth_app.state, "mark_setup_failed", None)
    if mark_failed_fn:
        combined_app.state.mark_setup_failed = mark_failed_fn  # type: ignore[attr-defined]

    return combined_app, jwt_issuer


async def _refresh_lock_timestamp_loop(lock_path: Path, interval_seconds: float = 3600.0) -> None:
    """Refresh the daemon's lock-file timestamp every ``interval_seconds`` so
    the 24h TTL sweep does not mistake a long-running daemon for a stale lock.

    Uses ``mcp_core.lifecycle.lock.refresh_lock_timestamp`` which silently
    no-ops on legacy 3-line locks (those will be migrated when the daemon
    next acquires a fresh lock).
    """
    import asyncio as _asyncio

    from mcp_core.lifecycle.lock import refresh_lock_timestamp

    while True:
        try:
            await _asyncio.sleep(interval_seconds)
        except _asyncio.CancelledError:
            return
        try:
            refresh_lock_timestamp(lock_path)
        except Exception:  # noqa: BLE001
            logger.opt(exception=True).debug("Failed to refresh lock timestamp at {}", lock_path)


# Registry populated by run_http_server so _refresh_capabilities_cache_after_save
# can locate the FastMCP instance by server name without receiving it as an arg
# (the credential-save hook only receives credentials + context, not mcp).
_mcp_registry: dict[str, Any] = {}


def _get_mcp_for_server(name: str) -> Any:
    """Return the registered FastMCP instance for *name*, or raise KeyError."""
    return _mcp_registry[name]


async def _refresh_capabilities_cache_after_save(server_name: str, lock_path: Path) -> None:
    """No-op stub kept for wiring back-compat after the daemon-bridge removal.

    Pre-stdio-pure, this helper rewrote ``<lock>.tools.json`` and touched
    ``<lock>.tools-list-changed`` so the smart-stdio bridge could forward a
    ``notifications/tools/list_changed`` to Claude Code. Without the bridge
    layer there is nothing to refresh -- the HTTP server's own
    capabilities response reflects the new credentials on the next
    ``tools/list`` request the client makes after credential save.

    The function is preserved (rather than fully deleted) because
    ``run_http_server`` wires it into the credential-save callback chain;
    the call sites stay green during the ecosystem migration and we can
    drop the wrapper once all consumers no longer rely on the post-save
    hook seam.
    """
    # Touch the args so static analyzers don't flag them as unused.
    _ = (server_name, lock_path)
    return None


async def run_http_server(
    mcp: FastMCP,
    *,
    server_name: str,
    relay_schema: dict[str, Any] | None = None,
    port: int = 0,
    host: str | None = None,
    open_browser: bool = True,
    on_credentials_saved: _Callback | None = None,
    on_step_submitted: _Callback | None = None,
    setup_complete_hook: Callable[..., None] | None = None,
    jwt_keys_dir: Path | None = None,
    custom_credential_form_html: Callable[..., str] | None = None,
    delegated_oauth: dict[str, Any] | None = None,
    auth_scope: AuthScope | None = None,
    auth_disabled: bool = False,
) -> None:
    """Start MCP server with local OAuth AS on 127.0.0.1.

    This is the main entry point for credential servers. It:
    1. Creates the OAuth app (credential form + token endpoints)
    2. Mounts the MCP transport at /mcp with Bearer auth
    3. Acquires a lifecycle lock
    4. Runs uvicorn (blocking)

    Args:
        mcp: FastMCP server instance.
        server_name: Identifier used for JWT iss/aud and credential storage.
        relay_schema: RelayConfigSchema dict describing the credential form.
            Mutually exclusive with ``delegated_oauth``.
        port: TCP port to bind. 0 means auto-find a free port.
        open_browser: Deprecated, ignored.
        on_credentials_saved: Optional callback invoked when user submits creds.
            Only used in relay (non-delegated) mode.
        on_step_submitted: Optional callback invoked when user submits a
            multi-step credential (OTP / 2FA password) via ``POST /otp``.
            Receives the step input dict and returns ``None`` (complete),
            an error dict, or another step-required dict.
            Only used in relay (non-delegated) mode.
        setup_complete_hook: Wires credential_state so background tasks
            (e.g. GDrive device code poll) can update the form's status.
            Invoked after the app is built with either arity:

            - ``hook(mark_complete)`` -- legacy 1-arg form, success only.
            - ``hook(mark_complete, mark_failed)`` -- new 2-arg form.
              ``mark_failed(key, error_message)`` signals ``error:<message>``
              to ``/setup-status`` so the browser stops polling and shows
              the error. Prefer the 2-arg form for new code.
        jwt_keys_dir: Directory for JWT key storage. Defaults to JWTIssuer's default.
        custom_credential_form_html: Optional ``(schema, submit_url) -> html``
            renderer used in place of the default credential form on GET
            /authorize. Lets consumers inject custom UX while reusing core
            OAuth plumbing. Only used in relay (non-delegated) mode.
        delegated_oauth: Dict configuring upstream OAuth delegation. Mutually
            exclusive with ``relay_schema``. See ``build_local_app`` for the
            expected keys.
        auth_scope: Optional middleware invoked after JWT verification. Passed
            through to ``build_local_app``. See ``BearerMCPApp`` for details.
    """
    import os
    import re
    import uvicorn

    from mcp_core.lifecycle.lock import LifecycleLock
    from mcp_core.storage.config_file import read_config

    # Edge auth deployment warning (per spec
    # 2026-05-01-stdio-pure-http-multiuser §4.2.1). When ``PUBLIC_URL`` points
    # to a non-localhost host but ``MCP_RELAY_PASSWORD`` is empty, the relay
    # form is reachable from the public Internet without authentication —
    # that's the wedge this gate closes. Localhost dev intentionally skips
    # the password; everyone else gets a startup warning so the misconfig
    # doesn't pass silently.
    _public_url = os.environ.get("PUBLIC_URL", "")
    _relay_password = os.environ.get("MCP_RELAY_PASSWORD", "")
    _is_localhost = bool(re.match(r"^https?://(localhost|127\.0\.0\.1)", _public_url))
    if _public_url and not _is_localhost and not _relay_password:
        logger.warning("HTTP mode public deployment without MCP_RELAY_PASSWORD — relay form is open to Internet")

    # Resolve port + host
    actual_port = port if port != 0 else find_free_port()
    actual_host = host or "127.0.0.1"

    # D17.2: Wrap on_credentials_saved to call _refresh_capabilities_cache_after_save
    # after a successful credential write.  We use a one-element list as a mutable
    # box so the wrapper closure can capture lock.path even though the LifecycleLock
    # is constructed after build_local_app (the lock path is deterministic from
    # server_name + actual_port, but we fill the box explicitly to stay DRY).
    _lock_path_box: list[Path] = []

    _original_on_credentials_saved = on_credentials_saved

    async def _on_credentials_saved_with_refresh(
        credentials: dict,
        context: dict,
    ) -> dict | None:
        result: dict | None = None
        if _original_on_credentials_saved is not None:
            import inspect as _inspect_creds
            from typing import cast

            raw = _original_on_credentials_saved(credentials, context)
            if _inspect_creds.isawaitable(raw):
                raw = cast("dict | None", await raw)
            result = cast("dict | None", raw)
        # Only refresh when the save succeeded (no error result).
        if not (isinstance(result, dict) and result.get("type") == "error"):
            if _lock_path_box:
                try:
                    await _refresh_capabilities_cache_after_save(server_name, _lock_path_box[0])
                except Exception:  # noqa: BLE001
                    logger.opt(exception=True).debug("Failed to refresh capabilities cache after save")
        return result

    # Use the wrapped callback only for relay (non-delegated) mode; delegated
    # OAuth doesn't go through on_credentials_saved at all.
    _effective_on_credentials_saved = (
        _on_credentials_saved_with_refresh if delegated_oauth is None else on_credentials_saved
    )

    # Build the combined app
    app, _jwt_issuer = build_local_app(
        mcp,
        server_name=server_name,
        relay_schema=relay_schema,
        on_credentials_saved=_effective_on_credentials_saved,
        on_step_submitted=on_step_submitted,
        jwt_keys_dir=jwt_keys_dir,
        custom_credential_form_html=custom_credential_form_html,
        delegated_oauth=delegated_oauth,
        auth_scope=auth_scope,
        auth_disabled=auth_disabled,
    )

    # Wire setup completion + failure callbacks. ``mark_setup_complete``
    # signals success; ``mark_setup_failed`` propagates background-task
    # errors (e.g. Google returns ``invalid_grant`` / ``expired_token`` for
    # the device code flow) to the browser form so it stops polling. The
    # hook receives both callbacks and MUST accept either arity for
    # backward compatibility:
    #   - Legacy 1-arg: ``hook(mark_complete)``
    #   - New 2-arg:    ``hook(mark_complete, mark_failed)``
    # Callers wiring only completion should migrate to the 2-arg form to
    # surface failures; the 1-arg form is detected and still supported.
    mark_fn = getattr(app.state, "mark_setup_complete", None)
    mark_failed_fn = getattr(app.state, "mark_setup_failed", None)
    if setup_complete_hook is not None and mark_fn is not None:
        import inspect as _inspect

        try:
            sig = _inspect.signature(setup_complete_hook)
            positional = [p for p in sig.parameters.values() if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
            arity = len(positional)
        except (TypeError, ValueError):
            # Builtins / C functions: assume new 2-arg signature.
            arity = 2

        if arity >= 2 and mark_failed_fn is not None:
            setup_complete_hook(mark_fn, mark_failed_fn)  # type: ignore[call-arg]
        else:
            setup_complete_hook(mark_fn)  # type: ignore[call-arg]

    # Issue a long-lived access token written into the lock file so any
    # in-process probe (e.g. health-check) can reach /mcp without going
    # through the browser OAuth flow.
    proxy_token = _jwt_issuer.issue_access_token(
        sub="http-server",
        expires_in_seconds=365 * 24 * 3600,  # 1 year
    )

    # Sweep stale locks for our server name BEFORE acquiring our own lock.
    # Without this, abnormal-exit residue (Windows OOM, taskkill, signal) can
    # accumulate dozens of stale `<server>-<port>.lock` files
    # — see 2026-04-28 wet-mcp 11-stale-lock pile-up.
    from mcp_core.lifecycle.lock import sweep_stale_locks

    swept = sweep_stale_locks(server_name)
    if swept:
        logger.info("Cleaned up {} stale lock file(s) for {}", swept, server_name)

    # Acquire lifecycle lock (stores pid, port, and proxy token)
    lock = LifecycleLock(name=server_name, port=actual_port, token=proxy_token)

    # Populate lock path box so the credential-save wrapper can use it.
    # lock.path is deterministic from (server_name, actual_port) and is safe
    # to read before ``with lock:`` enters.
    _lock_path_box.append(lock.path)

    # Register mcp instance so _refresh_capabilities_cache_after_save can find it
    # by server_name when the credential-save hook fires.
    _mcp_registry[server_name] = mcp

    with lock:
        # Decide whether to auto-open the relay form. Use schema-completeness
        # (is_schema_complete) instead of "config is None" so peer-share paths
        # writing partial entries (e.g. wet-mcp inheriting CRG cloud keys) do
        # not suppress the form when wet's required fields are still missing.
        existing_config = read_config(server_name)
        from mcp_core.auth.credential_form import is_schema_complete

        config_complete = (
            is_schema_complete(existing_config, relay_schema)
            if relay_schema is not None
            else existing_config is not None
        )

        if not config_complete:
            # Open the root URL ("/") so the OAuth-AS auto-bootstraps PKCE
            # and redirects to /authorize with valid parameters. Opening
            # /authorize directly returns ``invalid_request`` because the
            # endpoint requires client_id/redirect_uri/state/code_challenge —
            # see ``local_oauth_app.root()`` docstring ("one-URL UX without
            # exposing raw OAuth machinery").
            setup_url = f"http://{actual_host}:{actual_port}/"
            logger.info(
                "Configuration incomplete. Opening {} in browser to configure",
                setup_url,
            )
            # Auto-open browser so user sees relay form immediately on first
            # connect. Best-effort: any failure is reported via the ASCII
            # banner inside try_open_browser.
            from mcp_core.relay.browser import try_open_browser

            try_open_browser(setup_url)
        else:
            logger.info("Credentials already configured for {}", server_name)

        logger.info("Starting local MCP server on {}:{}", actual_host, actual_port)
        uv_config = uvicorn.Config(app, host=actual_host, port=actual_port, log_level="info")
        server = uvicorn.Server(uv_config)

        # Override install_signal_handlers to prevent premature exit on Windows.
        # Windows ProactorEventLoop + uvicorn signal handling can cause the
        # server to exit when background tasks complete.
        setattr(server, "install_signal_handlers", lambda: None)

        # Refresh the lock timestamp hourly so the 24h TTL sweep doesn't
        # mistake a long-running daemon for a stale lock. Cancelled on
        # server shutdown.
        import asyncio as _asyncio

        refresh_task = _asyncio.create_task(_refresh_lock_timestamp_loop(lock.path, interval_seconds=3600.0))

        try:
            await server.serve()
        finally:
            refresh_task.cancel()
            _mcp_registry.pop(server_name, None)  # cleanup module-level state
            try:
                await refresh_task
            except (_asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        logger.info("Server stopped (should_exit={})", server.should_exit)


class HttpServerHandle:
    """Handle returned by ``start_http_server_background``.

    Exposes the bound ``host`` and ``port`` plus an ``async close()`` that
    stops the uvicorn server cleanly. Parity with core-ts's
    ``runHttpServer`` return type.
    """

    def __init__(self, host: str, port: int, server: Any, task: Any) -> None:
        self.host = host
        self.port = port
        self._server = server
        self._task = task

    async def close(self) -> None:
        """Stop the background uvicorn server and wait for the task to finish."""
        import asyncio as _asyncio

        server = self._server
        task = self._task
        if server is not None:
            server.should_exit = True
        if task is not None and not task.done():
            try:
                await _asyncio.wait_for(task, timeout=5.0)
            except _asyncio.TimeoutError:
                task.cancel()
                try:
                    await task
                except (_asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass


async def start_http_server_background(
    mcp: FastMCP,
    *,
    server_name: str,
    relay_schema: dict[str, Any] | None = None,
    port: int = 0,
    host: str | None = None,
    on_credentials_saved: _Callback | None = None,
    on_step_submitted: _Callback | None = None,
    setup_complete_hook: Callable[..., None] | None = None,
    jwt_keys_dir: Path | None = None,
    custom_credential_form_html: Callable[..., str] | None = None,
    delegated_oauth: dict[str, Any] | None = None,
    auth_scope: AuthScope | None = None,
    startup_timeout: float = 5.0,
) -> HttpServerHandle:
    """Start a local OAuth + MCP server in the background and return a handle.

    Non-blocking variant of ``run_http_server``. Intended for stdio-mode
    credential-state fallback: a stdio MCP server needs a short-lived local
    HTTP credential form on a random port without blocking its own event
    loop. The returned ``HttpServerHandle`` exposes ``host``/``port`` and
    ``close()`` for clean shutdown once the form has been submitted.

    No ``LifecycleLock`` is acquired (the spawn is ephemeral and per-process);
    callers must ensure they only call this when credentials are missing and
    close the handle once ``on_credentials_saved`` has persisted the config.

    Args:
        mcp: FastMCP server instance. May be a minimal stub — the spawn is
            credential-form-focused and ``/mcp`` should not be exercised
            against it.
        server_name: Identifier used for JWT iss/aud and credential storage.
        relay_schema: RelayConfigSchema dict describing the credential form.
            Mutually exclusive with ``delegated_oauth``.
        port: TCP port to bind. 0 means auto-find a free port.
        host: Host to bind. Defaults to 127.0.0.1.
        on_credentials_saved: Callback invoked when the user submits creds.
        on_step_submitted: Callback for multi-step credential input (OTP / 2FA).
        setup_complete_hook: See ``run_http_server``.
        jwt_keys_dir: JWT key storage directory. Optional.
        custom_credential_form_html: Optional form renderer override.
        delegated_oauth: Delegated OAuth config. Mutually exclusive with
            ``relay_schema``.
        auth_scope: Optional middleware after JWT verification.
        startup_timeout: Seconds to wait for uvicorn to report ``started``
            before raising ``RuntimeError``. Defaults to 5s.

    Returns:
        ``HttpServerHandle`` pointing at the bound address.

    Raises:
        RuntimeError: If uvicorn does not start within ``startup_timeout``.
    """
    import asyncio

    import uvicorn

    actual_port = port if port != 0 else find_free_port()
    actual_host = host or "127.0.0.1"

    app, _jwt_issuer = build_local_app(
        mcp,
        server_name=server_name,
        relay_schema=relay_schema,
        on_credentials_saved=on_credentials_saved,
        on_step_submitted=on_step_submitted,
        jwt_keys_dir=jwt_keys_dir,
        custom_credential_form_html=custom_credential_form_html,
        delegated_oauth=delegated_oauth,
        auth_scope=auth_scope,
    )

    mark_fn = getattr(app.state, "mark_setup_complete", None)
    mark_failed_fn = getattr(app.state, "mark_setup_failed", None)
    if setup_complete_hook is not None and mark_fn is not None:
        import inspect as _inspect

        try:
            sig = _inspect.signature(setup_complete_hook)
            positional = [p for p in sig.parameters.values() if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
            arity = len(positional)
        except (TypeError, ValueError):
            arity = 2

        if arity >= 2 and mark_failed_fn is not None:
            setup_complete_hook(mark_fn, mark_failed_fn)  # type: ignore[call-arg]
        else:
            setup_complete_hook(mark_fn)  # type: ignore[call-arg]

    uv_config = uvicorn.Config(app, host=actual_host, port=actual_port, log_level="warning")
    server = uvicorn.Server(uv_config)
    # Prevent uvicorn from installing SIGINT/SIGTERM handlers that would
    # otherwise hijack the parent process (e.g. the stdio MCP server that
    # needs to keep responding to its own transport).
    setattr(server, "install_signal_handlers", lambda: None)

    task = asyncio.create_task(server.serve(), name=f"{server_name}-credential-form")

    deadline = asyncio.get_event_loop().time() + startup_timeout
    while asyncio.get_event_loop().time() < deadline:
        if getattr(server, "started", False):
            break
        if task.done():
            exc = task.exception()
            if exc is not None:
                raise exc
            raise RuntimeError("Local credential-form server exited before binding")
        await asyncio.sleep(0.05)
    else:
        server.should_exit = True
        raise RuntimeError(f"Local credential-form server did not start within {startup_timeout:.1f}s")

    logger.info("Local credential-form server ready at http://{}:{}", actual_host, actual_port)
    return HttpServerHandle(host=actual_host, port=actual_port, server=server, task=task)
