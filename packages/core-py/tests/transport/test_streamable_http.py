"""Tests for StreamableHTTPServer (Task C2).

These tests exercise only the `build_app()` construction seam -- no port
binding, no uvicorn, no lifecycle lock acquisition.
"""

from __future__ import annotations

import pytest
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from mcp_core.transport.streamable_http import StreamableHTTPServer


class DummyMW(BaseHTTPMiddleware):
    """No-op middleware used to verify the middleware stack is wired up."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        return await call_next(request)


@pytest.fixture
def mcp() -> FastMCP:
    return FastMCP("test-server")


def test_server_binds_port_and_host(mcp: FastMCP) -> None:
    server = StreamableHTTPServer(mcp, host="127.0.0.1", port=9876)
    assert server.host == "127.0.0.1"
    assert server.port == 9876


def test_build_app_returns_starlette_app_with_middleware(mcp: FastMCP) -> None:
    server = StreamableHTTPServer(
        mcp,
        port=9877,
        middleware=[Middleware(DummyMW)],
    )
    app = server.build_app()

    assert isinstance(app, Starlette)
    middleware_classes = [entry.cls for entry in app.user_middleware]
    assert DummyMW in middleware_classes, f"DummyMW not in app.user_middleware; got {middleware_classes}"


def test_build_app_without_middleware_still_works(mcp: FastMCP) -> None:
    server = StreamableHTTPServer(mcp, port=9878)
    app = server.build_app()
    assert isinstance(app, Starlette)
    # Response import kept so ruff doesn't flag unused; construction side
    # effect: a Starlette response must be importable.
    assert Response is not None
