"""Config resolution: env vars -> config file -> defaults -> None."""

import os
import re
from typing import Literal

from mcp_core.crypto.config_file import read_config

ConfigSource = Literal["env", "file", "defaults"] | None


class ResolvedConfig:
    """Result of config resolution."""

    __slots__ = ("config", "source")

    def __init__(
        self,
        config: dict[str, str] | None,
        source: ConfigSource,
    ) -> None:
        self.config = config
        self.source = source


def resolve_config(
    server_name: str,
    required_fields: list[str],
    defaults: dict[str, str] | None = None,
) -> ResolvedConfig:
    """Resolve config from multiple sources in priority order.

    1. Environment variables (MCP_{SERVER}_{FIELD})
    2. Encrypted config file
    3. Provided defaults
    4. None (trigger relay setup)

    Args:
        server_name: Server identifier.
        required_fields: List of required field names.
        defaults: Optional default values.

    Returns:
        ResolvedConfig with config dict and source.
    """
    # 1. Check env vars
    env_config: dict[str, str] = {}
    all_env_present = len(required_fields) > 0
    for field in required_fields:
        env_key = (
            "MCP_"
            + re.sub(r"-", "_", server_name).upper()
            + "_"
            + re.sub(r"-", "_", field).upper()
        )
        value = os.environ.get(env_key, "")
        if value:
            env_config[field] = value
        else:
            all_env_present = False

    if all_env_present:
        return ResolvedConfig(config=env_config, source="env")

    # 2. Check config file
    file_config = read_config(server_name)
    if file_config is not None:
        has_all = all(
            f in file_config and file_config[f] != "" for f in required_fields
        )
        if has_all:
            return ResolvedConfig(config=file_config, source="file")

    # 3. Check defaults
    if defaults is not None:
        has_all = all(f in defaults and defaults[f] != "" for f in required_fields)
        if has_all:
            return ResolvedConfig(config={**defaults}, source="defaults")

    # 4. Nothing found
    return ResolvedConfig(config=None, source=None)
