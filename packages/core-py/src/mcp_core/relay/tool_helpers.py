"""Helper to register `config__open_relay` MCP tool — HTTP-only mode.

After the stdio-pure + http-multi-user split, the relay config form is
served by the HTTP server itself at ``<PUBLIC_URL>/authorize``. The
``config__open_relay`` tool simply returns that URL and best-effort opens
the user's default browser. There is no daemon-bridge discovery, no
respawn, and no session deduplication -- the HTTP server's own session
tracking handles concurrent setup attempts.

In stdio mode, the relay form does not exist; the tool returns
``stdio_unsupported`` so plugin code can render a "switch to HTTP mode"
message instead of misleading the user with an unreachable URL.
"""

from __future__ import annotations

from typing import Any

from mcp_core.relay.browser import try_open_browser as _try_open_browser


def _build_open_relay_handler(server_name: str, public_url: str | None):
    """Closure factory — separated out for testability."""

    def open_relay() -> dict[str, Any]:
        """Open the relay form for {server_name}.

        Returns dict with keys:
          url: relay form URL (empty in stdio mode)
          browser_opened: True if the browser launched successfully
          status: configured | unconfigured | expired | session_active | stdio_unsupported
        """
        if public_url is None:
            return {
                "url": "",
                "browser_opened": False,
                "status": "stdio_unsupported",
            }
        url = f"{public_url.rstrip('/')}/authorize"
        opened = _try_open_browser(url)
        return {
            "url": url,
            "browser_opened": bool(opened),
            "status": "unconfigured",
        }

    if open_relay.__doc__ is not None:
        open_relay.__doc__ = open_relay.__doc__.replace("{server_name}", server_name)
    return open_relay


def register_open_relay_tool(mcp, server_name: str, public_url: str | None) -> None:
    """Register the ``config__open_relay`` MCP tool for ``server_name``.

    Consumer servers add this single line in their tool registry after the
    other ``config__*`` registrations::

        from mcp_core.relay.tool_helpers import register_open_relay_tool
        register_open_relay_tool(mcp, SERVER_NAME, PUBLIC_URL)

    Pass ``None`` for ``public_url`` when the server is running in stdio
    mode; the tool will return ``status: 'stdio_unsupported'`` so the
    caller can surface a clear "switch to HTTP mode" message.
    """
    handler = _build_open_relay_handler(server_name, public_url)
    description = (
        f"Open the relay configuration form for {server_name} in the user's "
        "browser. Returns the relay URL, whether the browser launched, and "
        "the current status."
    )

    @mcp.tool(name="config__open_relay", description=description)
    def _config_open_relay() -> dict[str, Any]:
        return handler()
