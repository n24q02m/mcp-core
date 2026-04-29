"""Helper to register `config__open_relay` MCP tool — D6 (Task 1.7).

Each consumer server calls ``register_open_relay_tool(mcp, SERVER_NAME, SCHEMA)``
to get the standard tool registered into its FastMCP instance. The tool, when
invoked by the LLM, returns the relay form URL and attempts to open the user's
browser. If the daemon is dead it auto-respawns; if a relay session is already
active in another Claude Code window, the handler returns ``session_active``
status without auto-opening a second browser tab.
"""

from __future__ import annotations

from typing import Any

from mcp_core.relay.browser import try_open_browser as _try_open_browser
from mcp_core.relay.session import is_session_active as _is_session_active_global
from mcp_core.transport.smart_stdio import (
    daemon_cred_state as _daemon_cred_state,
)
from mcp_core.transport.smart_stdio import (
    daemon_is_alive as _daemon_is_alive,
)
from mcp_core.transport.smart_stdio import (
    daemon_relay_url as _daemon_relay_url,
)
from mcp_core.transport.smart_stdio import (
    daemon_respawn as _daemon_respawn,
)


def _is_session_active_for_server(_server_name: str) -> bool:
    """Per-server session probe.

    The current session module tracks one global active form session at a
    time (Task 1.5), so the server name is currently ignored. Kept as a
    one-arg helper to give monkeypatch hooks a single, server-aware seam
    that future per-server session tracking can implement without
    refactoring callers.
    """
    return _is_session_active_global()


def _build_open_relay_handler(server_name: str, schema: dict[str, Any]):
    """Closure factory — separated out for testability."""

    def open_relay() -> dict[str, Any]:
        """Open the relay form for {server_name}.

        Returns dict with keys:
          url: relay form URL with session token
          browser_opened: True if the browser launched successfully
          status: configured | unconfigured | expired | session_active
        """
        if not _daemon_is_alive(server_name):
            url = _daemon_respawn(server_name)
        else:
            url = _daemon_relay_url(server_name)

        cred_state = _daemon_cred_state(server_name)

        if _is_session_active_for_server(server_name):
            return {
                "url": url,
                "browser_opened": False,
                "status": "session_active",
            }

        opened = _try_open_browser(url)
        return {
            "url": url,
            "browser_opened": bool(opened),
            "status": cred_state,
        }

    if open_relay.__doc__ is not None:
        open_relay.__doc__ = open_relay.__doc__.replace("{server_name}", server_name)
    return open_relay


def register_open_relay_tool(mcp, server_name: str, schema: dict[str, Any]) -> None:
    """Register the ``config__open_relay`` MCP tool for ``server_name``.

    Consumer servers add this single line in their tool registry after the
    other ``config__*`` registrations::

        from mcp_core.relay.tool_helpers import register_open_relay_tool
        register_open_relay_tool(mcp, SERVER_NAME, RELAY_SCHEMA)
    """
    handler = _build_open_relay_handler(server_name, schema)
    description = (
        f"Open the relay configuration form for {server_name} in the user's "
        "browser. Returns the relay URL, whether the browser launched, and the "
        "current credential state (configured | unconfigured | expired | "
        "session_active). Auto-respawns the daemon if it has died."
    )

    @mcp.tool(name="config__open_relay", description=description)
    def _config_open_relay() -> dict[str, Any]:
        return handler()
