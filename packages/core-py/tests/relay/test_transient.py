import threading
from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

from mcp_core.relay.transient import (
    _build_relay_app,
    _find_free_port,
    _generate_token,
    _render_form_fields,
    register_relay_form_tool,
)


class TestTransientUtils:
    def test_find_free_port(self):
        port = _find_free_port()
        assert isinstance(port, int)
        assert 1024 <= port <= 65535

    def test_generate_token(self):
        token = _generate_token()
        assert isinstance(token, str)
        assert len(token) > 0


class TestRenderFormFields:
    def test_fallback_when_schema_none(self):
        html, mode = _render_form_fields(None)
        assert mode == "json"
        assert "<textarea name='json'" in html

    def test_fallback_when_fields_missing(self):
        html, mode = _render_form_fields({})
        assert mode == "json"
        assert "<textarea name='json'" in html

    def test_renders_fields_from_schema(self):
        schema = {
            "fields": [
                {"name": "api_key", "label": "API Key", "type": "password", "required": True},
                {"name": "org_id", "label": "Org ID", "placeholder": "org-123"},
            ]
        }
        html, mode = _render_form_fields(schema)
        assert mode == "fields"
        assert "API Key" in html
        assert "type='password'" in html
        assert "name='api_key'" in html
        assert "required" in html
        assert "Org ID" in html
        assert "placeholder='org-123'" in html
        assert "name='org_id'" in html

    def test_skips_fields_without_name(self):
        schema = {"fields": [{"label": "No Name"}]}
        html, mode = _render_form_fields(schema)
        assert mode == "fields"
        assert html == ""

    def test_html_escaping(self):
        schema = {
            "fields": [
                {
                    "name": '"><script>alert(1)</script>',
                    "label": "<b>Bold</b>",
                    "placeholder": '">',
                }
            ]
        }
        html, mode = _render_form_fields(schema)
        assert "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in html
        assert "&lt;b&gt;Bold&lt;/b&gt;" in html
        assert "placeholder='&quot;&gt;'" in html


class TestRelayApp:
    @pytest.fixture
    def shutdown_event(self):
        return threading.Event()

    @pytest.fixture
    def on_save(self):
        return MagicMock()

    @pytest.fixture
    def client(self, on_save, shutdown_event):
        app = _build_relay_app("test-server", "valid-token", on_save, shutdown_event)
        return TestClient(app)

    def test_get_setup_requires_token(self, client):
        resp = client.get("/setup", params={"token": "wrong"})
        assert resp.status_code == 401
        assert resp.text == "invalid token"

    def test_get_setup_success(self, client):
        resp = client.get("/setup", params={"token": "valid-token"})
        assert resp.status_code == 200
        assert "test-server setup" in resp.text
        assert "relayForm" in resp.text

    def test_get_setup_escaping(self, on_save, shutdown_event):
        malicious_name = "</script><script>alert(1)</script>"
        app = _build_relay_app(malicious_name, "token", on_save, shutdown_event)
        client = TestClient(app)
        resp = client.get("/setup", params={"token": "token"})
        assert resp.status_code == 200
        # HTML escaping
        assert "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in resp.text
        # JS escaping (json.dumps)
        assert r"<\/script><script>alert(1)<\/script>" in resp.text

    def test_submit_requires_auth_header(self, client):
        resp = client.post("/setup/submit", json={"key": "val"})
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid token"

    def test_submit_requires_bearer_token(self, client):
        resp = client.post("/setup/submit", headers={"Authorization": "Basic xxx"}, json={"key": "val"})
        assert resp.status_code == 401

    def test_submit_requires_valid_bearer_token(self, client):
        resp = client.post("/setup/submit", headers={"Authorization": "Bearer wrong"}, json={"key": "val"})
        assert resp.status_code == 401

    def test_submit_invalid_json(self, client):
        # TestClient.post with 'content' and wrong content-type to simulate bad JSON
        resp = client.post(
            "/setup/submit",
            headers={"Authorization": "Bearer valid-token", "Content-Type": "application/json"},
            content="invalid-json",
        )
        assert resp.status_code == 400
        assert "invalid json" in resp.json()["error"]

    def test_submit_not_object(self, client):
        resp = client.post("/setup/submit", headers={"Authorization": "Bearer valid-token"}, json=[1, 2, 3])
        assert resp.status_code == 400
        assert "must be a JSON object" in resp.json()["error"]

    def test_submit_on_save_failure(self, on_save, shutdown_event):
        on_save.side_effect = Exception("save failed")
        app = _build_relay_app("test", "token", on_save, shutdown_event)
        client = TestClient(app)
        resp = client.post("/setup/submit", headers={"Authorization": "Bearer token"}, json={"k": "v"})
        assert resp.status_code == 500
        assert "on_save failed" in resp.json()["error"]

    def test_submit_success(self, client, on_save, shutdown_event):
        creds = {"api_key": "secret"}
        resp = client.post("/setup/submit", headers={"Authorization": "Bearer valid-token"}, json=creds)
        assert resp.status_code == 200
        assert resp.json() == {"status": "saved"}
        on_save.assert_called_once_with("test-server", creds)

        # Wait a bit for the shutdown thread to fire
        assert shutdown_event.wait(timeout=2.0)


class TestRegisterTool:
    @pytest.mark.asyncio
    async def test_register_and_invoke_tool(self):
        mcp = MagicMock()
        on_save = MagicMock()

        # Capture the tool function
        tool_func = None

        def mock_tool(name=None):
            def decorator(f):
                nonlocal tool_func
                tool_func = f
                return f

            return decorator

        mcp.tool = mock_tool

        register_relay_form_tool(mcp, "test-server", on_save)

        assert tool_func is not None
        assert tool_func.__name__ == "open_relay"

        # Mock dependencies for invoking the tool
        with (
            patch("mcp_core.relay.transient._find_free_port", return_value=12345),
            patch("mcp_core.relay.transient._generate_token", return_value="test-token"),
            patch("mcp_core.relay.transient.uvicorn.Server") as mock_server_cls,
            patch("mcp_core.relay.transient.threading.Thread") as mock_thread_cls,
            patch("mcp_core.relay.transient.socket.create_connection") as mock_connect,
            patch("mcp_core.relay.transient.webbrowser.open") as mock_browser_open,
            patch("mcp_core.relay.transient.asyncio.run") as mock_asyncio_run,
        ):
            mock_server = MagicMock()
            mock_server_cls.return_value = mock_server

            # Mock successful connection for the wait loop
            mock_connect.return_value.__enter__.return_value = MagicMock()

            # Mock asyncio.to_thread to just call the function directly
            async def mock_to_thread(f, *args, **kwargs):
                return f(*args, **kwargs)

            with patch("mcp_core.relay.transient.asyncio.to_thread", side_effect=mock_to_thread):
                result = await tool_func()

            assert result["url"] == "http://127.0.0.1:12345/setup?token=test-token"
            assert result["status"] == "browser_opened"

            # Check threads started (server and watchdog)
            assert mock_thread_cls.call_count == 2

            # Exercise _run_server and _watchdog
            # Thread 1: _run_server
            run_server_func = mock_thread_cls.call_args_list[0][1]["target"]
            run_server_func()
            mock_asyncio_run.assert_called_once()

            # Thread 2: _watchdog
            watchdog_func = mock_thread_cls.call_args_list[1][1]["target"]
            with patch("mcp_core.relay.transient.threading.Event.wait", return_value=True):
                watchdog_func()
            assert mock_server.should_exit is True

            # Check browser opened
            mock_browser_open.assert_called_once_with("http://127.0.0.1:12345/setup?token=test-token")

    @pytest.mark.asyncio
    async def test_register_and_invoke_tool_socket_retry(self):
        mcp = MagicMock()
        on_save = MagicMock()
        tool_func = None

        def mock_tool(name=None):
            def decorator(f):
                nonlocal tool_func
                tool_func = f
                return f

            return decorator

        mcp.tool = mock_tool

        register_relay_form_tool(mcp, "test-server", on_save)
        assert tool_func is not None

        with (
            patch("mcp_core.relay.transient._find_free_port", return_value=12345),
            patch("mcp_core.relay.transient._generate_token", return_value="test-token"),
            patch("mcp_core.relay.transient.uvicorn.Server"),
            patch("mcp_core.relay.transient.threading.Thread"),
            patch("mcp_core.relay.transient.socket.create_connection", side_effect=[OSError, MagicMock()]),
            patch("mcp_core.relay.transient.asyncio.sleep") as mock_sleep,
            patch("mcp_core.relay.transient.webbrowser.open"),
        ):
            # Mock asyncio.to_thread
            async def mock_to_thread(f, *args, **kwargs):
                return f(*args, **kwargs)

            with patch("mcp_core.relay.transient.asyncio.to_thread", side_effect=mock_to_thread):
                await tool_func()

            assert mock_sleep.call_count == 1

    @pytest.mark.asyncio
    async def test_browser_open_failure_is_non_fatal(self):
        mcp = MagicMock()
        on_save = MagicMock()
        tool_func = None

        def mock_tool(name=None):
            def decorator(f):
                nonlocal tool_func
                tool_func = f
                return f

            return decorator

        mcp.tool = mock_tool

        register_relay_form_tool(mcp, "test-server", on_save)
        assert tool_func is not None

        with (
            patch("mcp_core.relay.transient._find_free_port", return_value=12345),
            patch("mcp_core.relay.transient._generate_token", return_value="test-token"),
            patch("mcp_core.relay.transient.uvicorn.Server"),
            patch("mcp_core.relay.transient.threading.Thread"),
            patch("mcp_core.relay.transient.socket.create_connection"),
            patch("mcp_core.relay.transient.webbrowser.open", side_effect=Exception("browser error")),
        ):
            # Mock asyncio.to_thread
            async def mock_to_thread(f, *args, **kwargs):
                return f(*args, **kwargs)

            with patch("mcp_core.relay.transient.asyncio.to_thread", side_effect=mock_to_thread):
                result = await tool_func()
            assert result["status"] == "browser_opened"
            assert "Browser opened" in result["instructions"]
