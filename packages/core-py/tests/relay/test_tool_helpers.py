"""Tests for ``register_open_relay_tool``."""

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


def test_register_open_relay_tool_http(monkeypatch) -> None:
    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._try_open_browser",
        lambda url: True,
    )
    mcp = MagicMock()
    mock_decorator = MagicMock()
    mcp.tool.return_value = mock_decorator

    server_name = "test-server"
    public_url = "http://localhost:8000"

    register_open_relay_tool(mcp, server_name, public_url)

    # Verify decorator registration
    mcp.tool.assert_called_once()
    kwargs = mcp.tool.call_args.kwargs
    assert kwargs["name"] == "config__open_relay"
    assert server_name in kwargs["description"]

    # Verify the registered function
    mock_decorator.assert_called_once()
    registered_func = mock_decorator.call_args[0][0]

    result = registered_func()
    assert result["url"] == f"{public_url}/authorize"
    assert result["status"] == "unconfigured"
    assert result["browser_opened"] is True


def test_register_open_relay_tool_stdio() -> None:
    mcp = MagicMock()
    mock_decorator = MagicMock()
    mcp.tool.return_value = mock_decorator

    server_name = "test-server"

    register_open_relay_tool(mcp, server_name, None)

    # Verify decorator registration
    mcp.tool.assert_called_once()
    kwargs = mcp.tool.call_args.kwargs
    assert kwargs["name"] == "config__open_relay"

    # Verify the registered function
    mock_decorator.assert_called_once()
    registered_func = mock_decorator.call_args[0][0]

    result = registered_func()
    assert result["url"] == ""
    assert result["status"] == "stdio_unsupported"
    assert result["browser_opened"] is False
