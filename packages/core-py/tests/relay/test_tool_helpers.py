"""Tests for register_open_relay_tool helper (D6, Task 1.7)."""

from __future__ import annotations

from unittest.mock import MagicMock

from mcp_core.relay.tool_helpers import (
    _build_open_relay_handler,
    register_open_relay_tool,
)


SCHEMA = {
    "server": "demo",
    "fields": [
        {"name": "API_KEY", "label": "API Key", "required": True, "secret": True},
    ],
}


def test_register_calls_mcp_tool_decorator():
    mcp = MagicMock()
    register_open_relay_tool(mcp, "demo", SCHEMA)
    mcp.tool.assert_called()


def test_handler_returns_url_when_alive(monkeypatch):
    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._daemon_relay_url",
        lambda srv: "http://127.0.0.1:55317/setup?token=abc",
    )
    monkeypatch.setattr("mcp_core.relay.tool_helpers._daemon_is_alive", lambda srv: True)
    monkeypatch.setattr("mcp_core.relay.tool_helpers._is_session_active_for_server", lambda srv: False)
    monkeypatch.setattr("mcp_core.relay.tool_helpers._daemon_cred_state", lambda srv: "configured")
    opened: list[str] = []
    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._try_open_browser",
        lambda url: opened.append(url) or True,
    )

    handler = _build_open_relay_handler("demo", SCHEMA)
    result = handler()

    assert result["url"] == "http://127.0.0.1:55317/setup?token=abc"
    assert result["browser_opened"] is True
    assert result["status"] == "configured"
    assert opened == ["http://127.0.0.1:55317/setup?token=abc"]


def test_handler_session_active(monkeypatch):
    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._daemon_relay_url",
        lambda srv: "http://127.0.0.1:55317/setup",
    )
    monkeypatch.setattr("mcp_core.relay.tool_helpers._daemon_is_alive", lambda srv: True)
    monkeypatch.setattr("mcp_core.relay.tool_helpers._is_session_active_for_server", lambda srv: True)
    monkeypatch.setattr("mcp_core.relay.tool_helpers._daemon_cred_state", lambda srv: "configured")
    monkeypatch.setattr("mcp_core.relay.tool_helpers._try_open_browser", lambda url: False)

    handler = _build_open_relay_handler("demo", SCHEMA)
    result = handler()

    assert result["status"] == "session_active"
    # Browser is not auto-opened when another window holds the form session.
    assert result["browser_opened"] is False


def test_handler_respawns_when_dead(monkeypatch):
    state = {"alive": False}

    def respawn(srv: str) -> str:
        state["alive"] = True
        return "http://127.0.0.1:55320/setup?token=new"

    monkeypatch.setattr("mcp_core.relay.tool_helpers._daemon_is_alive", lambda srv: state["alive"])
    monkeypatch.setattr("mcp_core.relay.tool_helpers._daemon_respawn", respawn)
    monkeypatch.setattr("mcp_core.relay.tool_helpers._is_session_active_for_server", lambda srv: False)
    monkeypatch.setattr("mcp_core.relay.tool_helpers._daemon_cred_state", lambda srv: "unconfigured")
    monkeypatch.setattr("mcp_core.relay.tool_helpers._try_open_browser", lambda url: True)

    handler = _build_open_relay_handler("demo", SCHEMA)
    result = handler()

    assert result["url"] == "http://127.0.0.1:55320/setup?token=new"
    assert result["status"] == "unconfigured"
    assert state["alive"] is True
