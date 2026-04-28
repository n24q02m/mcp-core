"""Tests for the smart-stdio fast-handshake handlers.

These handlers let the proxy answer initialize / tools/list from disk in
milliseconds while the daemon is still cold-starting. The user-visible
property: tools appear in Claude Code's `/mcp` panel ~1s after session
start, not 30-60s.
"""

import json

import pytest

from mcp_core.transport.smart_stdio import (
    handle_initialize_from_cache,
    handle_tools_list_from_cache,
    persist_capabilities_cache,
)

# Pin the perceived mcp-core version for the whole module so handler tests
# don't depend on whichever version uv installed locally.
CACHED_VERSION = "1.9.0"


@pytest.fixture(autouse=True)
def _pin_current_version(monkeypatch):
    monkeypatch.setattr(
        "mcp_core.transport.smart_stdio._current_mcp_core_version",
        lambda: CACHED_VERSION,
    )


def test_handle_initialize_uses_cache(tmp_path):
    lock = tmp_path / "demo-1234.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    persist_capabilities_cache(
        lock,
        "demo",
        CACHED_VERSION,
        {"tools": {"listChanged": False}},
        [],
    )

    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25"},
    }
    response = handle_initialize_from_cache(lock, request)
    assert response is not None
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 1
    assert response["result"]["serverInfo"]["name"] == "demo"
    assert response["result"]["serverInfo"]["version"] == CACHED_VERSION
    assert response["result"]["capabilities"]["tools"]["listChanged"] is False
    # Echoes the client's protocol version when present.
    assert response["result"]["protocolVersion"] == "2025-11-25"


def test_handle_initialize_falls_back_to_default_protocol_version(tmp_path):
    lock = tmp_path / "demo-1234.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    persist_capabilities_cache(lock, "demo", CACHED_VERSION, {}, [])

    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
    response = handle_initialize_from_cache(lock, request)
    assert response is not None
    assert response["result"]["protocolVersion"] == "2025-11-25"


def test_handle_tools_list_uses_cache(tmp_path):
    lock = tmp_path / "demo-1234.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    persist_capabilities_cache(
        lock,
        "demo",
        CACHED_VERSION,
        {"tools": {"listChanged": False}},
        [
            {"name": "echo", "description": "echo", "inputSchema": {"type": "object"}},
            {"name": "ping", "description": "ping", "inputSchema": {"type": "object"}},
        ],
    )

    request = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    response = handle_tools_list_from_cache(lock, request)
    assert response is not None
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 2
    assert len(response["result"]["tools"]) == 2
    assert response["result"]["tools"][0]["name"] == "echo"
    assert response["result"]["tools"][1]["name"] == "ping"


def test_handle_returns_none_without_cache(tmp_path):
    lock = tmp_path / "demo-1234.lock"
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
    assert handle_initialize_from_cache(lock, request) is None
    assert handle_tools_list_from_cache(lock, request) is None


def test_initialize_cache_invalidates_on_version_mismatch(tmp_path, monkeypatch):
    lock = tmp_path / "demo-1234.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    persist_capabilities_cache(lock, "demo", "1.0.0", {}, [])
    # Override the autouse fixture: pin to a NEWER version so the cache is stale.
    monkeypatch.setattr(
        "mcp_core.transport.smart_stdio._current_mcp_core_version",
        lambda: "2.0.0",
    )

    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
    assert handle_initialize_from_cache(lock, request) is None
    assert handle_tools_list_from_cache(lock, request) is None


def test_initialize_id_is_preserved(tmp_path):
    lock = tmp_path / "demo-1234.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    persist_capabilities_cache(lock, "demo", CACHED_VERSION, {}, [])

    request = {
        "jsonrpc": "2.0",
        "id": "string-id-99",
        "method": "initialize",
    }
    response = handle_initialize_from_cache(lock, request)
    assert response is not None
    assert response["id"] == "string-id-99"


def test_response_serializable_to_json(tmp_path):
    """Sanity: the response shape must round-trip through json.dumps so the
    proxy can write it to stdout without surprises."""
    lock = tmp_path / "demo-1234.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    persist_capabilities_cache(
        lock,
        "demo",
        CACHED_VERSION,
        {"tools": {"listChanged": False}},
        [{"name": "echo", "inputSchema": {"type": "object"}}],
    )

    init = handle_initialize_from_cache(
        lock, {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
    )
    tools = handle_tools_list_from_cache(
        lock, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    )
    json.dumps(init)
    json.dumps(tools)
