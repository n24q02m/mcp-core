"""Tests for ``register_open_relay_tool`` -- HTTP-only mode."""

from __future__ import annotations

import sys
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
    register_open_relay_tool(mcp, "test-server", "http://127.0.0.1:8080")

    # Verify mcp.tool was called with correct arguments
    mcp.tool.assert_called_once()
    _, kwargs = mcp.tool.call_args
    assert kwargs["name"] == "config__open_relay"
    assert "test-server" in kwargs["description"]

    # The decorator returned by mcp.tool was called with the handler function
    decorator = mcp.tool.return_value
    decorator.assert_called_once()

    # Get the actual tool function that was registered
    registered_func = decorator.call_args[0][0]

    # Execute it and check result
    result = registered_func()
    assert result["url"] == "http://127.0.0.1:8080/authorize"
    assert result["status"] == "unconfigured"


def test_register_open_relay_tool_stdio() -> None:
    mcp = MagicMock()
    register_open_relay_tool(mcp, "test-server", None)

    mcp.tool.assert_called_once()
    decorator = mcp.tool.return_value
    registered_func = decorator.call_args[0][0]

    result = registered_func()
    assert result["status"] == "stdio_unsupported"
    assert result["url"] == ""


def test_handler_docstring_replacement() -> None:
    handler = _build_open_relay_handler("test-server", "http://127.0.0.1:8080")
    if sys.flags.optimize >= 2:
        assert handler.__doc__ is None
    else:
        assert handler.__doc__ is not None
        assert "test-server" in handler.__doc__
        assert "{server_name}" not in handler.__doc__


def test_handler_calls_browser_with_correct_url(monkeypatch) -> None:
    mock_open = MagicMock(return_value=True)
    monkeypatch.setattr("mcp_core.relay.tool_helpers._try_open_browser", mock_open)

    handler = _build_open_relay_handler("test-server", "http://127.0.0.1:8080")
    handler()

    mock_open.assert_called_once_with("http://127.0.0.1:8080/authorize")


def test_handler_with_multiple_trailing_slashes(monkeypatch) -> None:
    monkeypatch.setattr("mcp_core.relay.tool_helpers._try_open_browser", lambda url: True)
    handler = _build_open_relay_handler("test-server", "http://127.0.0.1:8080///")
    result = handler()
    assert result["url"] == "http://127.0.0.1:8080/authorize"


def test_handler_with_only_slash(monkeypatch) -> None:
    monkeypatch.setattr("mcp_core.relay.tool_helpers._try_open_browser", lambda url: True)
    handler = _build_open_relay_handler("test-server", "/")
    result = handler()
    assert result["url"] == "/authorize"
