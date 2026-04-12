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
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from starlette.applications import Starlette
    from starlette.types import ASGIApp, Receive, Scope, Send

    from mcp_core.oauth.jwt_issuer import JWTIssuer


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

    def __init__(self, inner: ASGIApp, jwt_issuer: JWTIssuer) -> None:
        self._inner = inner
        self._jwt_issuer = jwt_issuer

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
            self._jwt_issuer.verify_access_token(bearer)
        except Exception:
            from starlette.responses import Response

            resp = Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
            await resp(scope, receive, send)
            return

        await self._inner(scope, receive, send)


def build_local_app(
    mcp: FastMCP,
    *,
    server_name: str,
    relay_schema: dict[str, Any],
    on_credentials_saved: Callable[[dict[str, str]], dict | None] | None = None,
    jwt_keys_dir: Path | None = None,
) -> tuple[Starlette, JWTIssuer]:
    """Construct a combined Starlette app with OAuth AS + MCP transport.

    This is the testable construction seam. It builds the app without
    binding a port or running uvicorn.

    Args:
        mcp: FastMCP server instance.
        server_name: Identifier used for JWT iss/aud and credential storage.
        relay_schema: RelayConfigSchema dict describing the credential form.
        on_credentials_saved: Optional callback invoked when user submits creds.
        jwt_keys_dir: Directory for JWT key storage. Defaults to JWTIssuer's default.

    Returns:
        ``(app, jwt_issuer)`` tuple.
    """
    from contextlib import asynccontextmanager
    from typing import cast

    from mcp.server.fastmcp.server import StreamableHTTPASGIApp
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Route

    from mcp_core.auth.local_oauth_app import create_local_oauth_app
    from mcp_core.oauth.jwt_issuer import JWTIssuer

    # Build JWT issuer with optional custom keys directory
    jwt_issuer_kwargs: dict[str, Any] = {"server_name": server_name}
    if jwt_keys_dir is not None:
        jwt_issuer_kwargs["keys_dir"] = jwt_keys_dir
    jwt_issuer = JWTIssuer(**jwt_issuer_kwargs)

    # Create OAuth app to extract its routes
    oauth_app, _ = create_local_oauth_app(
        server_name=server_name,
        relay_schema=relay_schema,
        on_credentials_saved=on_credentials_saved,
        jwt_issuer=jwt_issuer,
    )

    # Create MCP ASGI handler via StreamableHTTPSessionManager
    session_manager = StreamableHTTPSessionManager(
        app=cast(Any, mcp)._mcp_server,
    )
    mcp_asgi_handler = StreamableHTTPASGIApp(session_manager)

    # Wrap with Bearer auth
    bearer_mcp_app = BearerMCPApp(inner=mcp_asgi_handler, jwt_issuer=jwt_issuer)

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

    # Forward mark_setup_complete from OAuth app to combined app
    mark_fn = getattr(oauth_app.state, "mark_setup_complete", None)
    if mark_fn:
        combined_app.state.mark_setup_complete = mark_fn  # type: ignore[attr-defined]

    return combined_app, jwt_issuer


async def run_local_server(
    mcp: FastMCP,
    *,
    server_name: str,
    relay_schema: dict[str, Any],
    port: int = 0,
    open_browser: bool = True,
    on_credentials_saved: Callable[[dict[str, str]], dict | None] | None = None,
    jwt_keys_dir: Path | None = None,
) -> None:
    """Start MCP server with local OAuth AS on 127.0.0.1.

    This is the main entry point for credential servers. It:
    1. Creates the OAuth app (credential form + token endpoints)
    2. Mounts the MCP transport at /mcp with Bearer auth
    3. Acquires a lifecycle lock
    4. Opens browser to /authorize if no credentials exist
    5. Runs uvicorn (blocking)

    Args:
        mcp: FastMCP server instance.
        server_name: Identifier used for JWT iss/aud and credential storage.
        relay_schema: RelayConfigSchema dict describing the credential form.
        port: TCP port to bind. 0 means auto-find a free port.
        open_browser: Whether to auto-open browser to /authorize when no
            credentials exist.
        on_credentials_saved: Optional callback invoked when user submits creds.
        jwt_keys_dir: Directory for JWT key storage. Defaults to JWTIssuer's default.
    """
    import os

    import uvicorn

    from mcp_core.lifecycle.lock import LifecycleLock
    from mcp_core.storage.config_file import read_config

    # Prevent write_config's _schedule_restart from killing the HTTP server.
    # In stdio mode, restart is needed to reload config. In HTTP mode, the
    # on_credentials_saved callback applies config immediately — no restart.
    os.environ["MCP_NO_RELOAD"] = "1"

    # Resolve port
    actual_port = port if port != 0 else find_free_port()

    # Build the combined app
    app, _jwt_issuer = build_local_app(
        mcp,
        server_name=server_name,
        relay_schema=relay_schema,
        on_credentials_saved=on_credentials_saved,
        jwt_keys_dir=jwt_keys_dir,
    )

    # Acquire lifecycle lock
    lock = LifecycleLock(name=server_name, port=actual_port)

    with lock:
        # Check if credentials already exist
        existing_config = read_config(server_name)
        if existing_config is None:
            logger.info(
                "No credentials found. Server at http://127.0.0.1:{}/authorize",
                actual_port,
            )
        else:
            logger.info("Credentials already configured for {}", server_name)

        logger.info("Starting local MCP server on 127.0.0.1:{}", actual_port)
        uv_config = uvicorn.Config(app, host="127.0.0.1", port=actual_port, log_level="info")
        server = uvicorn.Server(uv_config)

        # Override install_signal_handlers to prevent premature exit on Windows.
        # Windows ProactorEventLoop + uvicorn signal handling can cause the
        # server to exit when background tasks complete.
        server.install_signal_handlers = lambda: None

        await server.serve()
        logger.info("Server stopped (should_exit={})", server.should_exit)
