"""Tests for local_server module (OAuth AS + MCP transport combo).

Tests exercise app construction and helper functions without binding ports
or starting uvicorn. Full integration tests require a running server and
are left to E2E test suites.
"""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient

from mcp_core.transport.local_server import (
    BearerMCPApp,
    HttpServerHandle,
    build_local_app,
    find_free_port,
    start_http_server_background,
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
        route_paths = {getattr(r, "path", "") for r in app.routes}
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
        route_paths = {getattr(r, "path", "") for r in app.routes}
        assert "/mcp" in route_paths

    def test_threads_stable_sub_enabled_to_form(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        """stable_sub_enabled must reach the credential form via create_local_oauth_app."""
        import base64
        import hashlib
        import secrets as _secrets

        def _authorize_html(enabled: bool) -> str:
            app, _ = build_local_app(
                mcp=mcp,
                server_name="test-local-server",
                relay_schema=relay_schema,
                jwt_keys_dir=tmp_path / f"jwt-{enabled}",
                stable_sub_enabled=enabled,
            )
            verifier = _secrets.token_urlsafe(64)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            client = TestClient(app, base_url="http://localhost")
            resp = client.get(
                "/authorize",
                params={
                    "client_id": "c",
                    "redirect_uri": "http://localhost/cb",
                    "state": "s",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                },
            )
            return resp.text

        assert 'name="__sub_username"' in _authorize_html(True)
        assert 'name="__sub_username"' not in _authorize_html(False)

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

    def test_json_response_mode_keeps_stateful_session(self, relay_schema: dict, tmp_path: Path) -> None:
        """JSON mode must preserve a session across the initialize handshake.

        Cloudflare Containers do not reliably keep the POST-owned SSE response
        alive after the first response headers. JSON responses are the
        request/response variant of the same stateful MCP transport and must
        therefore keep ``notifications/initialized`` and the first tool
        request on the session that initialize created.
        """
        mcp = FastMCP("test-json-response")

        @mcp.tool()
        def hello() -> str:
            return "hello"

        app, jwt_issuer = build_local_app(
            mcp=mcp,
            server_name="test-json-response",
            relay_schema=relay_schema,
            jwt_keys_dir=tmp_path / "jwt-keys",
            json_response=True,
        )
        token = jwt_issuer.issue_access_token(sub="local-user")
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        with TestClient(app, raise_server_exceptions=True) as client:
            initialize = client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "1"},
                    },
                },
            )
            assert initialize.status_code == 200
            assert initialize.headers["content-type"].startswith("application/json")
            session_id = initialize.headers.get("mcp-session-id")
            assert session_id

            session_headers = {**headers, "Mcp-Session-Id": session_id}
            initialized = client.post(
                "/mcp",
                headers=session_headers,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            )
            assert initialized.status_code == 202

            listed = client.post(
                "/mcp",
                headers=session_headers,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            assert listed.status_code == 200
            assert listed.json()["result"]["tools"][0]["name"] == "hello"


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
        # RFC 9728: the challenge MUST advertise the protected-resource-metadata
        # URL so MCP clients can discover the authorization server (#260).
        assert "resource_metadata=" in www_auth

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
        www_auth = response.headers.get("www-authenticate", "")
        assert "resource_metadata=" in www_auth
        assert 'error="invalid_token"' in www_auth

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


class TestBearerMCPAppResourceMetadata:
    """The 401 ``WWW-Authenticate`` challenge must carry the RFC 9728
    ``resource_metadata`` URL so MCP clients can discover the authorization
    server. Regression coverage for #260 (deployed servers emitted a bare
    ``Bearer`` challenge from ``BearerMCPApp``, not ``OAuthMiddleware``).
    """

    @staticmethod
    def _make_app(tmp_path: Path):
        from starlette.applications import Starlette
        from starlette.routing import Route

        from mcp_core.oauth.jwt_issuer import JWTIssuer

        jwt_issuer = JWTIssuer(server_name="test", keys_dir=tmp_path / "jwt-keys")

        async def dummy_app(scope, receive, send):
            pass

        bearer_app = BearerMCPApp(inner=dummy_app, jwt_issuer=jwt_issuer)
        return Starlette(routes=[Route("/mcp", endpoint=bearer_app)])

    def test_missing_token_uses_public_url_when_set(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PUBLIC_URL", "https://wet-mcp.n24q02m.com")
        app = self._make_app(tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/mcp")
        assert response.status_code == 401
        www_auth = response.headers.get("www-authenticate", "")
        assert www_auth == (
            'Bearer resource_metadata="https://wet-mcp.n24q02m.com/.well-known/oauth-protected-resource"'
        )

    def test_invalid_token_uses_public_url_when_set(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PUBLIC_URL", "https://wet-mcp.n24q02m.com")
        app = self._make_app(tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/mcp", headers={"Authorization": "Bearer fake.jwt.token"})
        assert response.status_code == 401
        www_auth = response.headers.get("www-authenticate", "")
        assert www_auth == (
            'Bearer resource_metadata="https://wet-mcp.n24q02m.com/.well-known/oauth-protected-resource", '
            'error="invalid_token"'
        )

    def test_public_url_trailing_slash_normalized(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PUBLIC_URL", "https://wet-mcp.n24q02m.com/")
        app = self._make_app(tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/mcp")
        www_auth = response.headers.get("www-authenticate", "")
        assert "https://wet-mcp.n24q02m.com/.well-known/oauth-protected-resource" in www_auth
        assert ".com//.well-known" not in www_auth

    def test_missing_token_derives_from_host_when_public_url_unset(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PUBLIC_URL", raising=False)
        app = self._make_app(tmp_path)
        client = TestClient(app, base_url="http://example.test", raise_server_exceptions=False)
        response = client.post("/mcp")
        assert response.status_code == 401
        www_auth = response.headers.get("www-authenticate", "")
        assert www_auth == ('Bearer resource_metadata="http://example.test/.well-known/oauth-protected-resource"')

    def test_derives_scheme_from_x_forwarded_proto_when_public_url_unset(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PUBLIC_URL", raising=False)
        app = self._make_app(tmp_path)
        client = TestClient(app, base_url="http://proxied.test", raise_server_exceptions=False)
        response = client.post("/mcp", headers={"X-Forwarded-Proto": "https"})
        www_auth = response.headers.get("www-authenticate", "")
        assert www_auth == ('Bearer resource_metadata="https://proxied.test/.well-known/oauth-protected-resource"')


class TestBearerMCPAppAuthDisabled:
    """When auth_disabled=True, skip JWT validation and attach anonymous claims."""

    def test_allows_missing_authorization_when_disabled(self, tmp_path: Path) -> None:
        from mcp_core.oauth.jwt_issuer import JWTIssuer
        from starlette.responses import JSONResponse

        jwt_issuer = JWTIssuer(server_name="test", keys_dir=tmp_path / "jwt-keys")

        async def dummy_app(scope, receive, send):
            resp = JSONResponse({"ok": True})
            await resp(scope, receive, send)

        bearer_app = BearerMCPApp(inner=dummy_app, jwt_issuer=jwt_issuer, auth_disabled=True)

        from starlette.applications import Starlette
        from starlette.routing import Route

        app = Starlette(routes=[Route("/mcp", endpoint=bearer_app)])
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/mcp")
        assert response.status_code == 200
        assert response.json() == {"ok": True}

    def test_allows_garbage_token_when_disabled(self, tmp_path: Path) -> None:
        from mcp_core.oauth.jwt_issuer import JWTIssuer
        from starlette.responses import JSONResponse

        jwt_issuer = JWTIssuer(server_name="test", keys_dir=tmp_path / "jwt-keys")

        async def dummy_app(scope, receive, send):
            resp = JSONResponse({"ok": True})
            await resp(scope, receive, send)

        bearer_app = BearerMCPApp(inner=dummy_app, jwt_issuer=jwt_issuer, auth_disabled=True)

        from starlette.applications import Starlette
        from starlette.routing import Route

        app = Starlette(routes=[Route("/mcp", endpoint=bearer_app)])
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/mcp", headers={"Authorization": "Bearer not-a-jwt"})
        assert response.status_code == 200

    def test_anonymous_claims_passed_to_auth_scope_when_disabled(self, tmp_path: Path) -> None:
        from mcp_core.oauth.jwt_issuer import JWTIssuer
        from starlette.responses import JSONResponse

        jwt_issuer = JWTIssuer(server_name="test", keys_dir=tmp_path / "jwt-keys")
        captured_claims: list[dict] = []

        async def dummy_app(scope, receive, send):
            resp = JSONResponse({"ok": True})
            await resp(scope, receive, send)

        async def scope_capture(claims, next_):
            captured_claims.append(claims)
            await next_()

        bearer_app = BearerMCPApp(
            inner=dummy_app,
            jwt_issuer=jwt_issuer,
            auth_scope=scope_capture,
            auth_disabled=True,
        )

        from starlette.applications import Starlette
        from starlette.routing import Route

        app = Starlette(routes=[Route("/mcp", endpoint=bearer_app)])
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/mcp")
        assert response.status_code == 200
        assert len(captured_claims) == 1
        assert captured_claims[0] == {"sub": "anonymous", "anonymous": True}


# ---------------------------------------------------------------------------
# run_http_server (smoke test -- only verifiable parts)
# ---------------------------------------------------------------------------


def _mock_uvicorn_server():
    """Create a mock uvicorn.Server that does nothing on serve()."""
    mock_server = MagicMock()
    mock_server.serve = AsyncMock()
    return mock_server


class TestRunLocalServer:
    def test_logs_url_when_no_credentials(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        """Verify server logs authorize URL when credentials don't exist (no browser auto-open)."""
        mock_server = _mock_uvicorn_server()
        with (
            patch("mcp_core.storage.config_file.read_config", return_value=None),
            patch("uvicorn.Server", return_value=mock_server),
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

            mock_server.serve.assert_awaited_once()

    def _run_with_empty_config(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path, **kwargs) -> None:
        """Drive run_http_server down the "config incomplete" branch."""
        import asyncio

        mock_server = _mock_uvicorn_server()
        with (
            patch("mcp_core.storage.config_file.read_config", return_value=None),
            patch("uvicorn.Server", return_value=mock_server),
            patch("mcp_core.lifecycle.lock.LifecycleLock") as mock_lock,
        ):
            mock_lock.return_value.__enter__ = lambda self: self
            mock_lock.return_value.__exit__ = lambda self, *a: None
            asyncio.run(
                _run_server_for_test(
                    mcp,
                    relay_schema=relay_schema,
                    server_name="test",
                    port=12345,
                    jwt_keys_dir=tmp_path / "jwt-keys",
                    **kwargs,
                )
            )

    def test_open_browser_false_suppresses_auto_open(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        """A consumer that already hands the setup URL to the user by another
        route passes ``open_browser=False`` and must not get a second entry point
        into the same temporary server. imagine-mcp already passes
        ``open_browser=not public_url`` for exactly this reason."""
        with patch("mcp_core.relay.browser.try_open_browser") as mock_open:
            self._run_with_empty_config(mcp, relay_schema, tmp_path, open_browser=False)
            mock_open.assert_not_called()

    def test_open_browser_defaults_to_opening(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        """Default stays True -- first-run setup for the servers built on this
        function depends on the browser opening by itself."""
        with patch("mcp_core.relay.browser.try_open_browser") as mock_open:
            self._run_with_empty_config(mcp, relay_schema, tmp_path)
            mock_open.assert_called_once()
            assert mock_open.call_args[0][0].startswith("http://127.0.0.1:12345")

    def test_skips_browser_when_credentials_exist(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        """Verify server starts normally when credentials already exist."""
        mock_server = _mock_uvicorn_server()
        with (
            patch("mcp_core.storage.config_file.read_config", return_value={"api_key": "existing"}),
            patch("uvicorn.Server", return_value=mock_server),
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

            mock_server.serve.assert_awaited_once()

    def test_forwards_custom_credential_form_html_to_build_local_app(
        self, mcp: FastMCP, relay_schema: dict, tmp_path: Path
    ) -> None:
        """run_http_server must pass custom_credential_form_html through to build_local_app."""
        mock_server = _mock_uvicorn_server()
        captured: dict = {}

        def custom_renderer(_schema: dict, _url: str) -> str:
            return "<html></html>"

        original_build = build_local_app

        def spy_build(*args, **kwargs):
            captured["custom_credential_form_html"] = kwargs.get("custom_credential_form_html")
            captured["json_response"] = kwargs.get("json_response")
            return original_build(*args, **kwargs)

        with (
            patch("mcp_core.storage.config_file.read_config", return_value=None),
            patch("uvicorn.Server", return_value=mock_server),
            patch("mcp_core.lifecycle.lock.LifecycleLock") as mock_lock,
            patch("mcp_core.transport.local_server.build_local_app", side_effect=spy_build) as mock_build,
        ):
            mock_lock.return_value.__enter__ = lambda self: self
            mock_lock.return_value.__exit__ = lambda self, *a: None

            import asyncio

            from mcp_core.transport.local_server import run_http_server

            asyncio.run(
                run_http_server(
                    mcp,
                    server_name="test",
                    relay_schema=relay_schema,
                    port=12345,
                    jwt_keys_dir=tmp_path / "jwt-keys",
                    custom_credential_form_html=custom_renderer,
                    json_response=True,
                )
            )

            mock_build.assert_called_once()
            assert captured["custom_credential_form_html"] is custom_renderer
            assert captured["json_response"] is True

    def test_skips_browser_when_open_browser_false(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        """Verify webbrowser.open is NOT called when open_browser=False."""
        mock_server = _mock_uvicorn_server()
        with (
            patch("mcp_core.storage.config_file.read_config", return_value=None),
            patch("webbrowser.open") as mock_wb_open,
            patch("uvicorn.Server", return_value=mock_server),
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


class TestBuildLocalAppForwardsOnStepSubmitted:
    def test_forwards_on_step_submitted(self, tmp_path: Path) -> None:
        """build_local_app must pass on_step_submitted to create_local_oauth_app.

        End-to-end: POST /authorize with credentials returns otp_required,
        then POST /otp triggers on_step_submitted callback.
        """
        import re

        mcp = FastMCP("test-step")
        step_calls: list[dict] = []

        def on_step(data: dict, _context: dict) -> None:
            step_calls.append(data)
            return None  # complete

        def on_save(creds: dict, _context: dict) -> dict:
            return {
                "type": "otp_required",
                "text": "Enter OTP",
                "field": "otp_code",
                "input_type": "text",
            }

        app, _ = build_local_app(
            mcp=mcp,
            server_name="test-step",
            relay_schema={
                "server": "test-step",
                "displayName": "Test",
                "fields": [{"key": "PHONE", "label": "Phone", "type": "tel", "required": True}],
            },
            on_credentials_saved=on_save,
            on_step_submitted=on_step,
            jwt_keys_dir=tmp_path / "jwt-keys",
        )

        client = TestClient(app, base_url="http://localhost")

        # PKCE params
        import base64
        import hashlib
        import secrets

        verifier = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        params = {
            "client_id": "c",
            "redirect_uri": "http://x/cb",
            "state": "s",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }

        resp = client.get("/authorize", params=params)
        match = re.search(r'nonce=([^"&]+)', resp.text)
        assert match is not None, "Form should contain a nonce"
        nonce = match.group(1)

        creds_resp = client.post(f"/authorize?nonce={nonce}", json={"PHONE": "+1234567890"})
        assert creds_resp.status_code == 200
        assert creds_resp.json()["next_step"]["type"] == "otp_required"

        # Submit OTP -- this should hit on_step_submitted
        resp = client.post("/otp", json={"otp_code": "12345"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert step_calls == [{"otp_code": "12345"}]


class TestBuildLocalAppForwardsCustomFormRenderer:
    def test_forwards_custom_credential_form_html(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        """build_local_app must pass custom_credential_form_html to create_local_oauth_app.

        Calling GET /authorize should produce HTML from the custom renderer,
        not the default form template.
        """
        import base64
        import hashlib
        import secrets

        def custom_renderer(_schema: dict, submit_url: str, **_kwargs: object) -> str:
            return f"<!DOCTYPE html><html><body><h1>Custom Forwarded</h1><a href='{submit_url}'>x</a></body></html>"

        app, _ = build_local_app(
            mcp=mcp,
            server_name="test-local-server",
            relay_schema=relay_schema,
            jwt_keys_dir=tmp_path / "jwt-keys",
            custom_credential_form_html=custom_renderer,
        )
        client = TestClient(app, base_url="http://localhost")

        verifier = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        params = {
            "client_id": "c",
            "redirect_uri": "http://x/cb",
            "state": "s",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        resp = client.get("/authorize", params=params)
        assert resp.status_code == 200
        assert "<h1>Custom Forwarded</h1>" in resp.text
        assert "Enter your credentials" not in resp.text
        assert "nonce=" in resp.text


async def _run_server_for_test(
    mcp: FastMCP,
    *,
    relay_schema: dict,
    server_name: str,
    port: int,
    open_browser: bool = True,
    jwt_keys_dir: Path | None = None,
    setup_complete_hook=None,
) -> None:
    """Wrapper that calls run_http_server with test-friendly params."""
    from mcp_core.transport.local_server import run_http_server

    await run_http_server(
        mcp,
        server_name=server_name,
        relay_schema=relay_schema,
        port=port,
        open_browser=open_browser,
        jwt_keys_dir=jwt_keys_dir,
        setup_complete_hook=setup_complete_hook,
    )


class TestSetupCompleteHookArity:
    """``setup_complete_hook`` must support both legacy 1-arg and new 2-arg signatures.

    Legacy callers pass ``(mark_complete)`` only (pre-failure-propagation).
    New callers pass ``(mark_complete, mark_failed)`` to surface upstream
    device-code errors to the browser form.
    """

    def test_legacy_one_arg_hook_receives_mark_complete_only(
        self, mcp: FastMCP, relay_schema: dict, tmp_path: Path
    ) -> None:
        captured: list = []

        def legacy_hook(mark_complete):
            captured.append(("legacy", mark_complete))

        mock_server = _mock_uvicorn_server()
        with (
            patch("mcp_core.storage.config_file.read_config", return_value=None),
            patch("uvicorn.Server", return_value=mock_server),
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
                    setup_complete_hook=legacy_hook,
                )
            )

        assert len(captured) == 1
        assert captured[0][0] == "legacy"
        # Callable exposed so background task can signal completion.
        assert callable(captured[0][1])

    def test_two_arg_hook_receives_mark_complete_and_mark_failed(
        self, mcp: FastMCP, relay_schema: dict, tmp_path: Path
    ) -> None:
        captured: list = []

        def new_hook(mark_complete, mark_failed):
            captured.append(("new", mark_complete, mark_failed))

        mock_server = _mock_uvicorn_server()
        with (
            patch("mcp_core.storage.config_file.read_config", return_value=None),
            patch("uvicorn.Server", return_value=mock_server),
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
                    setup_complete_hook=new_hook,
                )
            )

        assert len(captured) == 1
        assert captured[0][0] == "new"
        assert callable(captured[0][1])
        assert callable(captured[0][2])


# ---------------------------------------------------------------------------
# build_local_app -- delegated_oauth option
# ---------------------------------------------------------------------------


def test_build_local_app_rejects_both_options():
    mcp = FastMCP(name="test")
    with pytest.raises(ValueError, match="mutually exclusive"):
        build_local_app(
            mcp,
            server_name="test",
            relay_schema={"fields": []},
            delegated_oauth={
                "flow": "redirect",
                "upstream": {
                    "authorize_url": "https://x.example",
                    "token_url": "https://y.example",
                    "client_id": "c",
                },
                "on_token_received": lambda t: None,
            },
        )


def test_build_local_app_delegated_mode_produces_app(tmp_path: Path):
    mcp = FastMCP(name="test")
    app, issuer = build_local_app(
        mcp,
        server_name="test-notion",
        jwt_keys_dir=tmp_path / "jwt-keys",
        delegated_oauth={
            "flow": "redirect",
            "upstream": {
                "authorize_url": "https://example.com/authorize",
                "token_url": "https://example.com/token",
                "client_id": "c",
                "client_secret": "s",
            },
            "on_token_received": lambda t: None,
        },
    )
    assert app is not None
    assert issuer.server_name == "test-notion"


class TestStartLocalServerBackground:
    """``start_http_server_background`` must bind a real port, stay non-blocking, and close cleanly."""

    async def test_returns_handle_and_serves_authorize(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        import httpx

        handle = await start_http_server_background(
            mcp,
            server_name="test-bg",
            relay_schema=relay_schema,
            jwt_keys_dir=tmp_path / "jwt-keys",
        )
        try:
            assert isinstance(handle, HttpServerHandle)
            assert handle.host == "127.0.0.1"
            assert handle.port > 0

            # /.well-known is public — hit it to prove server is serving.
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"http://{handle.host}:{handle.port}/.well-known/oauth-authorization-server",
                    timeout=5.0,
                )
            assert resp.status_code == 200
        finally:
            await handle.close()

    async def test_close_is_idempotent(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        handle = await start_http_server_background(
            mcp,
            server_name="test-bg-close",
            relay_schema=relay_schema,
            jwt_keys_dir=tmp_path / "jwt-keys",
        )
        await handle.close()
        # Second close must not raise.
        await handle.close()

    async def test_startup_timeout_raises(self, mcp: FastMCP, relay_schema: dict, tmp_path: Path) -> None:
        """If uvicorn never reports started within startup_timeout, raise RuntimeError."""

        class NeverStartsServer:
            should_exit = False
            started = False

            def __init__(self, *_a, **_kw) -> None:
                pass

            async def serve(self) -> None:
                import asyncio as _a

                while not self.should_exit:
                    await _a.sleep(0.05)

        with patch("uvicorn.Server", side_effect=lambda cfg: NeverStartsServer()):
            with pytest.raises(RuntimeError, match="did not start"):
                await start_http_server_background(
                    mcp,
                    server_name="test-bg-timeout",
                    relay_schema=relay_schema,
                    jwt_keys_dir=tmp_path / "jwt-keys",
                    startup_timeout=0.2,
                )


def test_build_local_app_auth_scope_not_invoked_on_unauthed_request(tmp_path: Path):
    """auth_scope must NOT be invoked when the request has no Bearer token."""
    calls: list[dict] = []

    async def scope(claims: dict, next_: object) -> None:
        calls.append(claims)

    mcp = FastMCP(name="test-scope")
    app, _ = build_local_app(
        mcp,
        server_name="test-scope",
        relay_schema={"fields": [{"key": "FOO", "label": "foo", "type": "text"}]},
        jwt_keys_dir=tmp_path / "jwt-keys",
        auth_scope=scope,
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.post("/mcp", json={})
        assert resp.status_code == 401
        assert calls == []
