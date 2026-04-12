"""Tests for local_server module (OAuth AS + MCP transport combo).

Tests exercise app construction and helper functions without binding ports
or starting uvicorn. Full integration tests require a running server and
are left to E2E test suites.
"""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import patch

import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient

from mcp_core.transport.local_server import (
    BearerMCPApp,
    build_local_app,
    find_free_port,
)


@pytest.fixture
def mcp() -> FastMCP:
    return FastMCP("test-local-server")


@pytest.fixture
def relay_schema() -> dict:
    return {
        "server": "test-local-server",
        "displayName": "Test Local Server",
        "description": "Test server for unit tests",
        "fields": [
            {
                "key": "api_key",
                "label": "API Key",
                "type": "password",
                "required": True,
            }
        ],
    }


# ---------------------------------------------------------------------------
# find_free_port
# ---------------------------------------------------------------------------


class TestFindFreePort:
    def test_returns_positive_integer(self) -> None:
        port = find_free_port()
        assert isinstance(port, int)
        assert port > 0

    def test_port_is_bindable(self) -> None:
        port = find_free_port()
        # The returned port should be immediately bindable
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))

    def test_two_calls_return_different_ports(self) -> None:
        port1 = find_free_port()
        port2 = find_free_port()
        # Not guaranteed but highly likely on a dev machine
        assert port1 != port2


# ---------------------------------------------------------------------------
# build_local_app
# ---------------------------------------------------------------------------


class TestBuildLocalApp:
    def test_returns_starlette_app_and_jwt_issuer(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        app, jwt_issuer = build_local_app(
            mcp=mcp,
            server_name="test-local-server",
            relay_schema=relay_schema,
            jwt_keys_dir=tmp_path / "jwt-keys",
        )
        from starlette.applications import Starlette

        assert isinstance(app, Starlette)
        assert jwt_issuer is not None

    def test_has_oauth_routes(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        app, _ = build_local_app(
            mcp=mcp,
            server_name="test-local-server",
            relay_schema=relay_schema,
            jwt_keys_dir=tmp_path / "jwt-keys",
        )
        route_paths = {r.path for r in app.routes}
        assert "/authorize" in route_paths
        assert "/token" in route_paths
        assert "/.well-known/oauth-authorization-server" in route_paths
        assert "/.well-known/oauth-protected-resource" in route_paths

    def test_has_mcp_route(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        app, _ = build_local_app(
            mcp=mcp,
            server_name="test-local-server",
            relay_schema=relay_schema,
            jwt_keys_dir=tmp_path / "jwt-keys",
        )
        route_paths = {r.path for r in app.routes}
        assert "/mcp" in route_paths

    def test_mcp_route_rejects_unauthenticated(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        app, _ = build_local_app(
            mcp=mcp,
            server_name="test-local-server",
            relay_schema=relay_schema,
            jwt_keys_dir=tmp_path / "jwt-keys",
        )
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/mcp", json={"jsonrpc": "2.0", "method": "ping", "id": 1})
        assert response.status_code == 401

    def test_mcp_route_accepts_valid_bearer(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        app, jwt_issuer = build_local_app(
            mcp=mcp,
            server_name="test-local-server",
            relay_schema=relay_schema,
            jwt_keys_dir=tmp_path / "jwt-keys",
        )
        token = jwt_issuer.issue_access_token(sub="local-user")
        client = TestClient(app, raise_server_exceptions=False)
        # The MCP endpoint should NOT return 401 with a valid token.
        # It may return some other status (e.g. 400 if the request body
        # is not a valid MCP message), but not 401.
        response = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "ping", "id": 1},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code != 401


# ---------------------------------------------------------------------------
# BearerMCPApp
# ---------------------------------------------------------------------------


class TestBearerMCPApp:
    def test_rejects_missing_authorization(self, tmp_path: Path) -> None:
        from mcp_core.oauth.jwt_issuer import JWTIssuer

        jwt_issuer = JWTIssuer(server_name="test", keys_dir=tmp_path / "jwt-keys")

        async def dummy_app(scope, receive, send):
            pass

        bearer_app = BearerMCPApp(inner=dummy_app, jwt_issuer=jwt_issuer)

        from starlette.applications import Starlette
        from starlette.routing import Route

        app = Starlette(routes=[Route("/mcp", endpoint=bearer_app)])
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/mcp")
        assert response.status_code == 401
        www_auth = response.headers.get("www-authenticate", "")
        assert "Bearer" in www_auth

    def test_rejects_invalid_token(self, tmp_path: Path) -> None:
        from mcp_core.oauth.jwt_issuer import JWTIssuer

        jwt_issuer = JWTIssuer(server_name="test", keys_dir=tmp_path / "jwt-keys")

        async def dummy_app(scope, receive, send):
            pass

        bearer_app = BearerMCPApp(inner=dummy_app, jwt_issuer=jwt_issuer)

        from starlette.applications import Starlette
        from starlette.routing import Route

        app = Starlette(routes=[Route("/mcp", endpoint=bearer_app)])
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/mcp",
            headers={"Authorization": "Bearer fake.jwt.token"},
        )
        assert response.status_code == 401

    def test_forwards_valid_token(self, tmp_path: Path) -> None:
        from mcp_core.oauth.jwt_issuer import JWTIssuer
        from starlette.responses import JSONResponse

        jwt_issuer = JWTIssuer(server_name="test", keys_dir=tmp_path / "jwt-keys")

        async def dummy_app(scope, receive, send):
            resp = JSONResponse({"ok": True})
            await resp(scope, receive, send)

        bearer_app = BearerMCPApp(inner=dummy_app, jwt_issuer=jwt_issuer)

        from starlette.applications import Starlette
        from starlette.routing import Route

        app = Starlette(routes=[Route("/mcp", endpoint=bearer_app)])
        client = TestClient(app, raise_server_exceptions=False)

        token = jwt_issuer.issue_access_token(sub="local-user")
        response = client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json() == {"ok": True}


# ---------------------------------------------------------------------------
# run_local_server (smoke test -- only verifiable parts)
# ---------------------------------------------------------------------------


class TestRunLocalServer:
    def test_opens_browser_when_no_credentials(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        """Verify webbrowser.open is called when credentials don't exist."""
        with (
            patch("mcp_core.storage.config_file.read_config", return_value=None),
            patch("webbrowser.open") as mock_wb_open,
            patch("uvicorn.run") as mock_uvicorn_run,
            patch("mcp_core.lifecycle.lock.LifecycleLock") as mock_lock,
        ):
            mock_lock.return_value.__enter__ = lambda self: self
            mock_lock.return_value.__exit__ = lambda self, *a: None

            import asyncio

            asyncio.run(
                _run_server_for_test(
                    mcp,
                    relay_schema=relay_schema,
                    server_name="test",
                    port=12345,
                    jwt_keys_dir=tmp_path / "jwt-keys",
                )
            )

            mock_wb_open.assert_called_once()
            assert "127.0.0.1:12345/authorize" in mock_wb_open.call_args[0][0]
            mock_uvicorn_run.assert_called_once()

    def test_skips_browser_when_credentials_exist(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        """Verify webbrowser.open is NOT called when credentials already exist."""
        with (
            patch("mcp_core.storage.config_file.read_config", return_value={"api_key": "existing"}),
            patch("webbrowser.open") as mock_wb_open,
            patch("uvicorn.run"),
            patch("mcp_core.lifecycle.lock.LifecycleLock") as mock_lock,
        ):
            mock_lock.return_value.__enter__ = lambda self: self
            mock_lock.return_value.__exit__ = lambda self, *a: None

            import asyncio

            asyncio.run(
                _run_server_for_test(
                    mcp,
                    relay_schema=relay_schema,
                    server_name="test",
                    port=12345,
                    jwt_keys_dir=tmp_path / "jwt-keys",
                )
            )

            mock_wb_open.assert_not_called()

    def test_skips_browser_when_open_browser_false(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        """Verify webbrowser.open is NOT called when open_browser=False."""
        with (
            patch("mcp_core.storage.config_file.read_config", return_value=None),
            patch("webbrowser.open") as mock_wb_open,
            patch("uvicorn.run"),
            patch("mcp_core.lifecycle.lock.LifecycleLock") as mock_lock,
        ):
            mock_lock.return_value.__enter__ = lambda self: self
            mock_lock.return_value.__exit__ = lambda self, *a: None

            import asyncio

            asyncio.run(
                _run_server_for_test(
                    mcp,
                    relay_schema=relay_schema,
                    server_name="test",
                    port=12345,
                    open_browser=False,
                    jwt_keys_dir=tmp_path / "jwt-keys",
                )
            )

            mock_wb_open.assert_not_called()


async def _run_server_for_test(
    mcp: FastMCP,
    *,
    relay_schema: dict,
    server_name: str,
    port: int,
    open_browser: bool = True,
    jwt_keys_dir: Path | None = None,
) -> None:
    """Wrapper that calls run_local_server with test-friendly params."""
    from mcp_core.transport.local_server import run_local_server

    await run_local_server(
        mcp,
        server_name=server_name,
        relay_schema=relay_schema,
        port=port,
        open_browser=open_browser,
        jwt_keys_dir=jwt_keys_dir,
    )
