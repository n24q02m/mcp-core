"""Server mode management: local-only vs relay-configured.

Persists user's choice to skip relay permanently by storing a mode marker
in the existing config.enc encrypted storage.
"""

import logging
from typing import Literal

from mcp_core.storage.config_file import (
    delete_config,
    read_config,
    write_config,
)

logger = logging.getLogger(__name__)

_MODE_KEY = "_mode"
_LOCAL_MODE_VALUE = "local"

ServerMode = Literal["local", "configured"] | None


def set_local_mode(server_name: str) -> None:
    """Mark server as local-only (user explicitly skipped relay).

    Writes {"_mode": "local"} to config.enc[server_name].

    Args:
        server_name: Server identifier.
    """
    write_config(server_name, {_MODE_KEY: _LOCAL_MODE_VALUE})
    logger.debug("Set local mode for %s", server_name)


def get_mode(server_name: str) -> ServerMode:
    """Get server mode.

    Args:
        server_name: Server identifier.

    Returns:
        "local" if local mode set, "configured" if has other keys, None if empty.
    """
    config = read_config(server_name)
    if config is None:
        return None

    if config.get(_MODE_KEY) == _LOCAL_MODE_VALUE:
        return "local"

    # Has keys other than _mode (or _mode with different value) -> configured
    non_mode_keys = [k for k in config if k != _MODE_KEY]
    if non_mode_keys:
        return "configured"

    return None


def clear_mode(server_name: str) -> None:
    """Remove mode marker (allows relay to trigger again).

    Deletes the server's config entry entirely.

    Args:
        server_name: Server identifier.
    """
    delete_config(server_name)
    logger.debug("Cleared mode for %s", server_name)
