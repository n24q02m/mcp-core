"""Agent config file writer for MCP server installation.

Detects installed agents (Claude Code, Codex, Copilot, Antigravity, Cursor,
Windsurf, OpenCode) and writes MCP server entries to their config files.

Full implementation lands in a follow-up Phase I task. This stub establishes
the API surface for the `<server>(action="install_agent", targets=[...])`
MCP tool action.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

AgentName = Literal[
    "claude-code",
    "codex",
    "copilot",
    "antigravity",
    "cursor",
    "windsurf",
    "opencode",
]


class AgentInstaller:
    def __init__(self, server_name: str, url: str, token: str | None = None) -> None:
        self._server_name = server_name
        self._url = url
        self._token = token

    def install(self, target: AgentName) -> Path:
        """Install MCP server entry into target agent's config file.

        Returns the path of the file that was modified.
        """
        raise NotImplementedError(
            "Implementation follows in a Phase I follow-up task"
        )

    def uninstall(self, target: AgentName) -> Path:
        raise NotImplementedError(
            "Implementation follows in a Phase I follow-up task"
        )
