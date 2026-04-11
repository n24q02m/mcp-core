"""Agent config file writer for MCP server installation.

Reads + updates each agent's config file to add or remove an MCP server entry
pointing at a Streamable HTTP 2025-11-25 endpoint. Supports the subset of
agents whose config format is publicly documented and stable.

Config location + format per agent:

- ``claude-code``: ``~/.claude.json`` JSON with ``mcpServers`` object
- ``cursor``: ``~/.cursor/mcp.json`` JSON with ``mcpServers`` object
- ``codex``: ``~/.codex/config.toml`` TOML with ``[mcp_servers.<name>]`` table
- ``windsurf``: ``~/.codeium/windsurf/mcp_config.json`` JSON with
  ``mcpServers`` object
- ``opencode``: ``~/.config/opencode/config.json`` JSON with ``mcpServers``
  object
- ``copilot``, ``antigravity``: raise ``NotImplementedError`` because no
  stable config format is published yet; callers should handle this
  gracefully.

Atomic write: changes are staged to a sibling temp file and renamed over the
original so a crash mid-write cannot corrupt the agent config.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Literal

import tomllib

import tomli_w

AgentName = Literal[
    "claude-code",
    "codex",
    "copilot",
    "antigravity",
    "cursor",
    "windsurf",
    "opencode",
]

SUPPORTED_AGENTS: tuple[AgentName, ...] = (
    "claude-code",
    "cursor",
    "codex",
    "windsurf",
    "opencode",
)

UNSUPPORTED_REASON = {
    "copilot": "GitHub Copilot CLI MCP config location is not yet a stable public API",
    "antigravity": "Google Antigravity MCP config format is not yet documented",
}


def _agent_config_path(agent: AgentName, home: Path) -> Path:
    if agent == "claude-code":
        return home / ".claude.json"
    if agent == "cursor":
        return home / ".cursor" / "mcp.json"
    if agent == "codex":
        return home / ".codex" / "config.toml"
    if agent == "windsurf":
        return home / ".codeium" / "windsurf" / "mcp_config.json"
    if agent == "opencode":
        return home / ".config" / "opencode" / "config.json"
    raise ValueError(f"unknown agent: {agent}")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return {}
    loaded = json.loads(text)
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} does not contain a JSON object at the root")
    return loaded


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_name, path)
    except Exception:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def _build_http_entry(url: str, token: str | None) -> dict[str, Any]:
    entry: dict[str, Any] = {"type": "http", "url": url}
    if token is not None:
        entry["headers"] = {"Authorization": f"Bearer {token}"}
    return entry


class AgentInstaller:
    """Writes MCP server entries into agent config files."""

    def __init__(
        self,
        server_name: str,
        url: str,
        token: str | None = None,
        *,
        home: Path | None = None,
    ) -> None:
        if not server_name:
            raise ValueError("server_name must be non-empty")
        if not url:
            raise ValueError("url must be non-empty")
        self._server_name = server_name
        self._url = url
        self._token = token
        self._home = home if home is not None else Path.home()

    @property
    def supported_agents(self) -> tuple[AgentName, ...]:
        return SUPPORTED_AGENTS

    def install(self, target: AgentName) -> Path:
        """Add the server entry to ``target``'s config file. Returns the path."""
        if target in UNSUPPORTED_REASON:
            raise NotImplementedError(f"{target}: {UNSUPPORTED_REASON[target]}")
        if target not in SUPPORTED_AGENTS:
            raise ValueError(f"unknown agent: {target}")

        path = _agent_config_path(target, self._home)
        if target == "codex":
            return self._install_codex(path)
        return self._install_json(path)

    def uninstall(self, target: AgentName) -> Path:
        """Remove the server entry from ``target``'s config file. Returns the path."""
        if target in UNSUPPORTED_REASON:
            raise NotImplementedError(f"{target}: {UNSUPPORTED_REASON[target]}")
        if target not in SUPPORTED_AGENTS:
            raise ValueError(f"unknown agent: {target}")

        path = _agent_config_path(target, self._home)
        if target == "codex":
            return self._uninstall_codex(path)
        return self._uninstall_json(path)

    def _install_json(self, path: Path) -> Path:
        config = _read_json(path)
        servers = config.setdefault("mcpServers", {})
        if not isinstance(servers, dict):
            raise ValueError(f"{path}: 'mcpServers' is not an object")
        servers[self._server_name] = _build_http_entry(self._url, self._token)
        _atomic_write(path, json.dumps(config, indent=2) + "\n")
        return path

    def _uninstall_json(self, path: Path) -> Path:
        config = _read_json(path)
        servers = config.get("mcpServers")
        if isinstance(servers, dict) and self._server_name in servers:
            del servers[self._server_name]
            _atomic_write(path, json.dumps(config, indent=2) + "\n")
        return path

    def _install_codex(self, path: Path) -> Path:
        config = _read_toml(path)
        servers = config.setdefault("mcp_servers", {})
        if not isinstance(servers, dict):
            raise ValueError(f"{path}: 'mcp_servers' is not a table")
        entry: dict[str, Any] = {"url": self._url, "transport": "streamable-http"}
        if self._token is not None:
            entry["headers"] = {"Authorization": f"Bearer {self._token}"}
        servers[self._server_name] = entry
        _atomic_write(path, tomli_w.dumps(config))
        return path

    def _uninstall_codex(self, path: Path) -> Path:
        config = _read_toml(path)
        servers = config.get("mcp_servers")
        if isinstance(servers, dict) and self._server_name in servers:
            del servers[self._server_name]
            _atomic_write(path, tomli_w.dumps(config))
        return path
