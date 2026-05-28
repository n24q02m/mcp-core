"""Tests for ``register_open_relay_tool`` -- HTTP-only mode."""

from __future__ import annotations

from unittest.mock import MagicMock

from mcp_core.relay.tool_helpers import _build_open_relay_handler, register_open_relay_tool


def test_returns_authorize_url_when_public_url_set(monkeypatch) -> None:
    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._try_open_browser",
        lambda url: True,
    )
    handler = _build_open_relay_handler("test-server", "http://127.0.0.1:8080")
    result = handler()
    assert result["url"] == "http://127.0.0.1:8080/authorize"
    assert result["status"] == "unconfigured"
    assert result["browser_opened"] is True


def test_strips_trailing_slash_in_public_url(monkeypatch) -> None:
    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._try_open_browser",
        lambda url: True,
    )
    handler = _build_open_relay_handler("test-server", "http://127.0.0.1:8080/")
    result = handler()
    assert result["url"] == "http://127.0.0.1:8080/authorize"


def test_returns_stdio_unsupported_when_public_url_none() -> None:
    handler = _build_open_relay_handler("test-server", None)
    result = handler()
    assert result["status"] == "stdio_unsupported"
    assert result["url"] == ""
    assert result["browser_opened"] is False


def test_browser_open_failure_still_returns_url(monkeypatch) -> None:
    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._try_open_browser",
        lambda url: False,
    )
    handler = _build_open_relay_handler("test-server", "http://127.0.0.1:8080")
    result = handler()
    assert result["url"] == "http://127.0.0.1:8080/authorize"
    assert result["browser_opened"] is False


def test_register_open_relay_tool_calls_mcp_tool_with_correct_args(monkeypatch) -> None:
    # Mock _try_open_browser to avoid side effects
    monkeypatch.setattr("mcp_core.relay.tool_helpers._try_open_browser", lambda url: True)

    mcp = MagicMock()
    server_name = "test-server"
    public_url = "http://localhost:8080"

    register_open_relay_tool(mcp, server_name, public_url)

    # Check if mcp.tool was called as a decorator
    mcp.tool.assert_called_once()
    args, kwargs = mcp.tool.call_args
    assert kwargs["name"] == "config__open_relay"
    assert server_name in kwargs["description"]

    # The decorator returns a function that takes the function to decorate
    # In register_open_relay_tool:
    # @mcp.tool(...)
    # def _config_open_relay(): ...
    # This means mcp.tool(...)(_config_open_relay) was called.
    # MagicMock's return value for a call is another MagicMock.
    # So mcp.tool(...) returns a mock decorator.
    decorator = mcp.tool.return_value
    decorator.assert_called_once()

    # Get the actual tool function that was decorated
    tool_func = decorator.call_args[0][0]

    # Execute the tool function and check result
    result = tool_func()
    assert result["url"] == "http://localhost:8080/authorize"
    assert result["status"] == "unconfigured"


def test_register_open_relay_tool_stdio_mode(monkeypatch) -> None:
    mcp = MagicMock()
    server_name = "test-server"
    public_url = None

    register_open_relay_tool(mcp, server_name, public_url)

    decorator = mcp.tool.return_value
    tool_func = decorator.call_args[0][0]

    result = tool_func()
    assert result["status"] == "stdio_unsupported"
    assert result["url"] == ""
