"""Streamable HTTP 2025-11-25 transport server.

Design notes:
- FastMCP 3.2.3 exposes `FastMCP.http_app(path, middleware, transport, ...)` which
  builds a Starlette app pre-configured for the requested MCP transport. We pass
  `transport="streamable-http"` and our middleware list directly to that factory.
  FastMCP internally uses `starlette.middleware.Middleware` (aliased as
  `ASGIMiddleware`) for the middleware parameter, so a standard Starlette
  `Middleware(Cls, **kwargs)` entry is the correct shape.
- `build_app()` is the testable seam: it is a pure construction step that can
  be inspected (`app.user_middleware`) without binding a port or running
  uvicorn. Tests call it directly.
- `run()` is the runtime entry point: it acquires a `LifecycleLock` (either the
  caller-supplied one, or a default keyed by `(mcp.name, port)`) BEFORE binding
  the port, so two instances of the same server cannot race on the same port.
- Middleware is attached at construction time (not via `app.add_middleware()`),
  because the latter is only valid on a pre-build Starlette app and re-triggers
  stack assembly. Passing `middleware=...` to FastMCP's factory is the
  supported path.
- Heavy imports (`fastmcp`, `uvicorn`, `LifecycleLock`) are deferred: FastMCP
  lives behind TYPE_CHECKING so we don't pay its import cost when consumers
  only need the class for type annotations, and uvicorn / LifecycleLock are
  imported inside `run()` since they are only needed at runtime.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from starlette.applications import Starlette
    from starlette.middleware import Middleware

    from mcp_core.lifecycle.lock import LifecycleLock


class StreamableHTTPServer:
    """MCP server with Streamable HTTP 2025-11-25 transport.

    Wraps a FastMCP instance to produce a Starlette app configured with the
    Streamable HTTP transport, an optional middleware stack (typically
    OAuthMiddleware), and a cross-process lifecycle lock that prevents two
    instances from binding the same port.
    """

    def __init__(
        self,
        mcp: FastMCP,
        *,
        host: str = "127.0.0.1",
        port: int,
        middleware: Sequence[Middleware] | None = None,
        lock: LifecycleLock | None = None,
    ) -> None:
        self._mcp = mcp
        self._host = host
        self._port = port
        self._middleware: list[Middleware] = list(middleware) if middleware else []
        self._lock = lock

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    def build_app(self) -> Starlette:
        """Build the Starlette app for this server.

        This is the testable seam -- it returns a fully configured Starlette
        app without binding a port or starting uvicorn. Tests can inspect the
        returned app's `user_middleware` list to verify middleware wiring.
        """
        # FastMCP.http_app is not in all published type stubs; cast for ty.
        http_app = cast(Any, self._mcp).http_app
        app: Starlette = http_app(
            transport="streamable-http",
            middleware=self._middleware or None,
        )
        return app

    def run(self) -> None:
        """Start the server (blocking).

        Acquires the lifecycle lock BEFORE binding the port, then hands the
        configured Starlette app to uvicorn. Releases the lock on shutdown.
        """
        import uvicorn

        from mcp_core.lifecycle.lock import LifecycleLock

        lock = self._lock or LifecycleLock(name=self._mcp.name, port=self._port)
        with lock:
            app = self.build_app()
            uvicorn.run(app, host=self._host, port=self._port, log_level="info")
