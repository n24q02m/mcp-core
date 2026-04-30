"""Unit tests for the transient stdio-mode relay helper.

Covers ``mcp_core.relay.transient.register_relay_form_tool`` and its
``_find_free_port`` primitive. The transient helper is used by stdio-mode
plugins which have no long-running HTTP daemon: the ``config__open_relay``
tool spawns a one-shot HTTP server in the plugin process when called, opens
the user's browser to the credential form, and self-shutdowns after the
user submits credentials or after the configured idle timeout.
"""

from __future__ import annotations

import asyncio
import re
import socket

import httpx
import pytest

from mcp_core.relay.transient import _find_free_port, register_relay_form_tool


def test_find_free_port_returns_unused_port():
    """``_find_free_port`` asks the kernel for an unused ephemeral port."""
    port = _find_free_port()
    assert 1024 <= port <= 65535
    # Port should be immediately bindable; the kernel released it on close.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", port))
        s.listen()


@pytest.mark.asyncio
async def test_register_creates_open_relay_tool(monkeypatch):
    """``register_relay_form_tool`` registers ``config__open_relay`` returning a URL."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(name="test-server")
    # Short timeout so the watchdog thread doesn't linger 600s past test exit.
    register_relay_form_tool(mcp, "test-server", lambda *a: None, timeout_seconds=2)

    tools = await mcp.list_tools()
    tool_names = [t.name for t in tools]
    assert "config__open_relay" in tool_names

    monkeypatch.setattr("webbrowser.open", lambda url: None)
    result = await mcp.call_tool("config__open_relay", {})
    assert "127.0.0.1" in str(result)


@pytest.mark.asyncio
async def test_relay_form_save_callback_fires_on_submit(monkeypatch):
    """Submitting the form fires the ``on_save`` callback and shuts the server down."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(name="test-server")
    saved: list[tuple[str, dict]] = []
    register_relay_form_tool(mcp, "test-server", lambda name, creds: saved.append((name, creds)))

    monkeypatch.setattr("webbrowser.open", lambda url: None)
    result = await mcp.call_tool("config__open_relay", {})

    match = re.search(r"http://127\.0\.0\.1:(\d+)/setup\?token=([A-Za-z0-9_\-]+)", str(result))
    assert match, f"expected setup URL in result, got: {result!r}"
    port, token = match.groups()

    # Allow the background uvicorn thread time to bind the port.
    await asyncio.sleep(0.5)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"http://127.0.0.1:{port}/setup/submit",
            headers={"Authorization": f"Bearer {token}"},
            json={"api_key": "test-key-123"},
        )
    assert resp.status_code == 200, resp.text

    # Allow the on_save callback to fire (it's invoked synchronously inside
    # the request handler, but the callback list is populated on a separate
    # uvicorn worker thread). The submit handler also schedules a 0.5s
    # delayed shutdown so the response can flush — wait long enough to see
    # the callback's side effect.
    await asyncio.sleep(0.7)

    assert ("test-server", {"api_key": "test-key-123"}) in saved


@pytest.mark.asyncio
async def test_invalid_token_rejected(monkeypatch):
    """A submission with the wrong bearer token must return 401."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(name="test-server")
    register_relay_form_tool(mcp, "test-server", lambda *a: None, timeout_seconds=2)

    monkeypatch.setattr("webbrowser.open", lambda url: None)
    result = await mcp.call_tool("config__open_relay", {})

    match = re.search(r":(\d+)/setup", str(result))
    assert match, f"expected setup URL in result, got: {result!r}"
    port = match.group(1)

    await asyncio.sleep(0.5)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"http://127.0.0.1:{port}/setup/submit",
            headers={"Authorization": "Bearer wrong-token"},
            json={"api_key": "fake"},
        )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_relay_schema_renders_labeled_inputs(monkeypatch):
    """When ``relay_schema`` is provided, GET /setup renders labeled inputs.

    Restores UX parity with HTTP-daemon mode (``feedback_relay_mode_ui_parity.md``):
    the user sees one input per credential field with the schema's label as
    the visible text, not a generic JSON paste textarea.
    """
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(name="test-server")
    schema = {
        "fields": [
            {"name": "api_key", "label": "API Key", "type": "password", "required": True},
            {"name": "workspace_id", "label": "Workspace", "type": "text"},
        ]
    }
    register_relay_form_tool(
        mcp,
        "test-server",
        lambda *a: None,
        relay_schema=schema,
        timeout_seconds=2,
    )

    monkeypatch.setattr("webbrowser.open", lambda url: None)
    result = await mcp.call_tool("config__open_relay", {})

    match = re.search(r"http://127\.0\.0\.1:(\d+)/setup\?token=([A-Za-z0-9_\-]+)", str(result))
    assert match, f"expected setup URL in result, got: {result!r}"
    port, token = match.groups()

    await asyncio.sleep(0.5)

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"http://127.0.0.1:{port}/setup",
            params={"token": token},
        )
    assert resp.status_code == 200
    body = resp.text

    # Expect the schema-driven path: one labeled input per field, with the
    # generic JSON textarea absent (form mode is "fields", not "json").
    assert "name='api_key'" in body
    assert "name='workspace_id'" in body
    assert "API Key" in body
    assert "Workspace" in body
    assert "data-mode='fields'" in body
    # Generic JSON textarea fallback must NOT be rendered when a schema is given.
    assert "name='json'" not in body
