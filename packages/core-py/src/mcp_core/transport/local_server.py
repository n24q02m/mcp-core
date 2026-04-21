"""Local MCP server with self-hosted OAuth 2.1 AS.

Entry point for credential servers running in local mode (single-user,
127.0.0.1). Combines:
1. OAuth 2.1 AS (credential form + token exchange) -- serves /authorize, /token, /.well-known/*
2. MCP Streamable HTTP transport -- serves /mcp with Bearer auth
3. Lifecycle lock -- prevents two instances on same port
4. Auto-open browser -- opens /authorize on first run when no credentials exist
"""

from __future__ import annotations

import socket
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Union

from loguru import logger

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from starlette.applications import Starlette
    from starlette.types import ASGIApp, Receive, Scope, Send

    from mcp_core.oauth.jwt_issuer import JWTIssuer


# Callback may be sync or async. Async lets callbacks perform I/O without
# running-loop hacks. See mcp_core.auth.local_oauth_app for details.
_Callback = Callable[[dict[str, str]], Union[dict | None, Awaitable[dict | None]]]

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

    def __init__(self, inner: ASGIApp, jwt_issuer: JWTIssuer, auth_scope: AuthScope | None = None) -> None:
        self._inner = inner
        self._jwt_issuer = jwt_issuer
        self._auth_scope = auth_scope

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._inner(scope, receive, send)
            return

        # Extract Bearer token from headers
        bearer: str | None = None
        for key, value in scope.get("headers", []):
            if key == b"authorization":
                auth_str = value.decode("utf-8", errors="ignore")
                scheme, _, token_part = auth_str.partition(" ")
                if scheme.lower() == "bearer" and token_part.strip():
                    bearer = token_part.strip()
                break

        if not bearer:
            from starlette.responses import Response

            resp = Response(
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await resp(scope, receive, send)
            return

        try:
            claims = self._jwt_issuer.verify_access_token(bearer)
        except Exception:
            from starlette.responses import Response

            resp = Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
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
    custom_credential_form_html: Callable[[dict[str, Any], str], str] | None = None,
    delegated_oauth: dict[str, Any] | None = None,
    auth_scope: AuthScope | None = None,
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

        # Create OAuth app to extract its routes
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

    # Wrap with Bearer auth
    bearer_mcp_app = BearerMCPApp(inner=mcp_asgi_handler, jwt_issuer=jwt_issuer, auth_scope=auth_scope)

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


async def run_local_server(
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
    custom_credential_form_html: Callable[[dict[str, Any], str], str] | None = None,
    delegated_oauth: dict[str, Any] | None = None,
    auth_scope: AuthScope | None = None,
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
    import uvicorn

    from mcp_core.lifecycle.lock import LifecycleLock
    from mcp_core.storage.config_file import read_config

    # Resolve port + host
    actual_port = port if port != 0 else find_free_port()
    actual_host = host or "127.0.0.1"

    # Build the combined app
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

    # Acquire lifecycle lock
    lock = LifecycleLock(name=server_name, port=actual_port)

    with lock:
        # Check if credentials already exist
        existing_config = read_config(server_name)
        if existing_config is None:
            logger.info(
                "No credentials found. Open http://{}:{} in browser to configure",
                actual_host,
                actual_port,
            )
        else:
            logger.info("Credentials already configured for {}", server_name)

        logger.info("Starting local MCP server on {}:{}", actual_host, actual_port)
        uv_config = uvicorn.Config(app, host=actual_host, port=actual_port, log_level="info")
        server = uvicorn.Server(uv_config)

        # Override install_signal_handlers to prevent premature exit on Windows.
        # Windows ProactorEventLoop + uvicorn signal handling can cause the
        # server to exit when background tasks complete.
        setattr(server, "install_signal_handlers", lambda: None)

        await server.serve()
        logger.info("Server stopped (should_exit={})", server.should_exit)


class LocalServerHandle:
    """Handle returned by ``start_local_server_background``.

    Exposes the bound ``host`` and ``port`` plus an ``async close()`` that
    stops the uvicorn server cleanly. Use this from credential-state code
    paths (stdio fallback) that need a non-blocking local credential form
    on a random port. Parity with core-ts's ``runLocalServer`` return type.
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


async def start_local_server_background(
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
    custom_credential_form_html: Callable[[dict[str, Any], str], str] | None = None,
    delegated_oauth: dict[str, Any] | None = None,
    auth_scope: AuthScope | None = None,
    startup_timeout: float = 5.0,
) -> LocalServerHandle:
    """Start a local OAuth + MCP server in the background and return a handle.

    Non-blocking variant of ``run_local_server``. Intended for stdio-mode
    credential-state fallback: a stdio MCP server needs a short-lived local
    HTTP credential form on a random port without blocking its own event
    loop. The returned ``LocalServerHandle`` exposes ``host``/``port`` and
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
        setup_complete_hook: See ``run_local_server``.
        jwt_keys_dir: JWT key storage directory. Optional.
        custom_credential_form_html: Optional form renderer override.
        delegated_oauth: Delegated OAuth config. Mutually exclusive with
            ``relay_schema``.
        auth_scope: Optional middleware after JWT verification.
        startup_timeout: Seconds to wait for uvicorn to report ``started``
            before raising ``RuntimeError``. Defaults to 5s.

    Returns:
        ``LocalServerHandle`` pointing at the bound address.

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
    return LocalServerHandle(host=actual_host, port=actual_port, server=server, task=task)
