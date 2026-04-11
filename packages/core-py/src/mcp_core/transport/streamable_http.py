"""Streamable HTTP 2025-11-25 transport base.

Thin wrapper around FastMCP that adds OAuth 2.1 middleware, lifecycle lock,
and session management. Credential servers subclass or instantiate directly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_core.auth.middleware import OAuthMiddleware
    from mcp_core.lifecycle.lock import LifecycleLock


class StreamableHTTPServer:
    """MCP server with Streamable HTTP 2025-11-25 transport."""

    def __init__(
        self,
        mcp: "FastMCP",
        *,
        host: str = "127.0.0.1",
        port: int,
        auth: "OAuthMiddleware | None" = None,
        lock: "LifecycleLock | None" = None,
    ) -> None:
        self._mcp = mcp
        self._host = host
        self._port = port
        self._auth = auth
        self._lock = lock

    def run(self) -> None:
        """Start the server (blocking)."""
        from mcp_core.lifecycle.lock import LifecycleLock

        lock = self._lock or LifecycleLock(name=self._mcp.name, port=self._port)
        with lock:
            app = self._mcp.streamable_http_app()  # ty: ignore[unresolved-attribute]
            if self._auth is not None:
                app.add_middleware(type(self._auth), **self._auth.kwargs)
            import uvicorn

            uvicorn.run(app, host=self._host, port=self._port, log_level="info")
