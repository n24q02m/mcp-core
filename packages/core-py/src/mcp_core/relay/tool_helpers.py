"""Helper to register `config__open_relay` MCP tool — HTTP-only mode.

After the stdio-pure + http-multi-user split, the relay config form is
served by the HTTP server itself at ``<PUBLIC_URL>/authorize``. The
``config__open_relay`` tool directs the user to that URL.

When the connected client declares URL-mode elicitation
(``capabilities.elicitation.url``, SEP-1036), the tool asks the client to
present a consent prompt and open the URL via ``session.elicit_url`` so the
credential form is opened out-of-band without the LLM in the loop. Clients
that do NOT declare the capability fall back to the legacy behaviour: the
tool returns the URL and best-effort opens the user's default browser
server-side. There is no daemon-bridge discovery, no respawn, and no
session deduplication -- the HTTP server's own session tracking handles
concurrent setup attempts.

In stdio mode, the relay form does not exist; the tool returns
``stdio_unsupported`` so plugin code can render a "switch to HTTP mode"
message instead of misleading the user with an unreachable URL.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastmcp import Context

from mcp_core.relay.browser import try_open_browser as _try_open_browser

# Maps the client's ElicitResult.action to the tool's outcome field.
_ELICIT_ACTION_MAP = {"accept": "accepted", "decline": "declined", "cancel": "cancelled"}


def _build_open_relay_handler(server_name: str, public_url: str | None):
    """Closure factory for the legacy (browser-open) fallback path."""

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


def _client_supports_url_elicitation(session: Any) -> bool:
    """True if the connected client declared URL-mode elicitation capability.

    Reads ``client_params.capabilities.elicitation.url`` defensively so a
    missing, partial, or non-standard session object degrades to ``False``
    (falling back to the legacy browser-open path) rather than raising.
    """
    params = getattr(session, "client_params", None)
    capabilities = getattr(params, "capabilities", None)
    elicitation = getattr(capabilities, "elicitation", None)
    return getattr(elicitation, "url", None) is not None


async def _run_open_relay(
    server_name: str,
    public_url: str | None,
    session: Any,
) -> dict[str, Any]:
    """Resolve the ``config__open_relay`` result for one invocation.

    URL-mode elicitation is used only when ``public_url`` is set and the
    client declared the capability; otherwise the legacy fallback dict is
    returned unchanged.
    """
    fallback = _build_open_relay_handler(server_name, public_url)
    if public_url is None:
        return fallback()
    if not _client_supports_url_elicitation(session):
        return fallback()

    url = f"{public_url.rstrip('/')}/authorize"
    message = f"Open the {server_name} configuration page to enter your credentials securely in your browser."
    result = await session.elicit_url(
        message=message,
        url=url,
        elicitation_id=str(uuid4()),
    )
    action = getattr(result, "action", "accept")
    return {
        "url": url,
        "browser_opened": False,
        "status": "unconfigured",
        "elicitation": _ELICIT_ACTION_MAP.get(action, action),
    }


def register_open_relay_tool(mcp, server_name: str, public_url: str | None) -> None:
    """Register the ``config__open_relay`` MCP tool for ``server_name``.

    Consumer servers add this single line in their tool registry after the
    other ``config__*`` registrations::

        from mcp_core.relay.tool_helpers import register_open_relay_tool
        register_open_relay_tool(mcp, SERVER_NAME, PUBLIC_URL)

    Pass ``None`` for ``public_url`` when the server is running in stdio
    mode; the tool will return ``status: 'stdio_unsupported'`` so the
    caller can surface a clear "switch to HTTP mode" message.

    The registered handler takes an injected ``Context`` (fastmcp strips it
    from the tool's input schema, so the tool surface is unchanged) and uses
    URL-mode elicitation when the client supports it, falling back to the
    legacy browser-open dict otherwise.
    """
    # Deliberately conditional, and worded to match the core-ts helper so both
    # sides read as one decision. The handler returns ``browser_opened: False``
    # whenever no browser could be launched (headless, CI, the env-guard, no
    # desktop session), and this text is read by a model that then speaks for
    # the tool. "Open the ... form in the user's browser" reads as a guarantee,
    # so a model can report "opened it in your browser" while the result says
    # otherwise -- the user is then waiting on a tab that will never appear.
    # The URL is what the tool always delivers; the browser is a convenience on
    # top, and the wording says so in that order.
    description = (
        f"Get the relay configuration URL for {server_name}, opening it in the "
        "user's browser when possible. Returns the relay URL, whether the "
        "browser launched, and the current status."
    )

    @mcp.tool(name="config__open_relay", description=description)
    async def _config_open_relay(ctx: Context) -> dict[str, Any]:
        try:
            session = ctx.session
        except Exception:
            # Guarantee the fallback path even if session access fails.
            session = None
        return await _run_open_relay(server_name, public_url, session)
