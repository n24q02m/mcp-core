"""Relay client: passphrase generation, session creation, polling.

Also exposes ``register_relay_form_tool`` -- the stdio-mode counterpart to
``register_open_relay_tool`` (HTTP-daemon mode). See ``transient`` module.
"""

from mcp_core.relay.browser import try_open_browser
from mcp_core.relay.client import (
    RelaySession,
    create_session,
    generate_passphrase,
    poll_for_responses,
    poll_for_result,
    send_message,
)
from mcp_core.relay.transient import register_relay_form_tool
from mcp_core.relay.wordlist import WORDLIST

__all__ = [
    "WORDLIST",
    "RelaySession",
    "create_session",
    "generate_passphrase",
    "poll_for_responses",
    "poll_for_result",
    "register_relay_form_tool",
    "send_message",
    "try_open_browser",
]
