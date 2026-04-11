"""Tests for mcp_core.install.agents."""

from __future__ import annotations

import json
from pathlib import Path

import tomllib
from typing import cast

import pytest

from mcp_core.install.agents import (
    SUPPORTED_AGENTS,
    UNSUPPORTED_REASON,
    AgentInstaller,
    AgentName,
)


@pytest.fixture
def installer(tmp_path: Path) -> AgentInstaller:
    return AgentInstaller(
        server_name="wet-mcp",
        url="http://127.0.0.1:9876/mcp",
        home=tmp_path,
    )


class TestClaudeCode:
    def test_install_writes_mcp_servers_entry(self, installer: AgentInstaller, tmp_path: Path) -> None:
        path = installer.install("claude-code")
        assert path == tmp_path / ".claude.json"
        config = json.loads(path.read_text(encoding="utf-8"))
        assert config["mcpServers"]["wet-mcp"] == {
            "type": "http",
            "url": "http://127.0.0.1:9876/mcp",
        }

    def test_install_preserves_existing_servers(self, installer: AgentInstaller, tmp_path: Path) -> None:
        existing = {"mcpServers": {"other-srv": {"type": "http", "url": "http://localhost:1111/mcp"}}}
        (tmp_path / ".claude.json").write_text(json.dumps(existing), encoding="utf-8")

        installer.install("claude-code")

        config = json.loads((tmp_path / ".claude.json").read_text(encoding="utf-8"))
        assert "other-srv" in config["mcpServers"]
        assert "wet-mcp" in config["mcpServers"]

    def test_install_with_token_adds_authorization_header(self, tmp_path: Path) -> None:
        inst = AgentInstaller(
            server_name="wet-mcp",
            url="http://127.0.0.1:9876/mcp",
            token="sekrit-token",
            home=tmp_path,
        )
        path = inst.install("claude-code")
        config = json.loads(path.read_text(encoding="utf-8"))
        entry = config["mcpServers"]["wet-mcp"]
        assert entry["headers"] == {"Authorization": "Bearer sekrit-token"}

    def test_uninstall_removes_entry(self, installer: AgentInstaller, tmp_path: Path) -> None:
        installer.install("claude-code")
        installer.uninstall("claude-code")
        config = json.loads((tmp_path / ".claude.json").read_text(encoding="utf-8"))
        assert "wet-mcp" not in config["mcpServers"]

    def test_uninstall_on_missing_file_is_noop(self, installer: AgentInstaller, tmp_path: Path) -> None:
        # Should not raise even though the file does not exist yet.
        installer.uninstall("claude-code")
        # Still no file created.
        assert not (tmp_path / ".claude.json").exists()


class TestCursor:
    def test_install_writes_cursor_mcp_json(self, installer: AgentInstaller, tmp_path: Path) -> None:
        path = installer.install("cursor")
        assert path == tmp_path / ".cursor" / "mcp.json"
        config = json.loads(path.read_text(encoding="utf-8"))
        assert config["mcpServers"]["wet-mcp"]["url"] == "http://127.0.0.1:9876/mcp"


class TestCodex:
    def test_install_writes_toml_table(self, installer: AgentInstaller, tmp_path: Path) -> None:
        path = installer.install("codex")
        assert path == tmp_path / ".codex" / "config.toml"
        config = tomllib.loads(path.read_text(encoding="utf-8"))
        assert config["mcp_servers"]["wet-mcp"] == {
            "url": "http://127.0.0.1:9876/mcp",
            "transport": "streamable-http",
        }

    def test_uninstall_removes_toml_entry(self, installer: AgentInstaller, tmp_path: Path) -> None:
        installer.install("codex")
        installer.uninstall("codex")
        path = tmp_path / ".codex" / "config.toml"
        config = tomllib.loads(path.read_text(encoding="utf-8"))
        assert "wet-mcp" not in config.get("mcp_servers", {})


class TestWindsurfAndOpencode:
    def test_install_windsurf(self, installer: AgentInstaller, tmp_path: Path) -> None:
        path = installer.install("windsurf")
        assert path == tmp_path / ".codeium" / "windsurf" / "mcp_config.json"
        config = json.loads(path.read_text(encoding="utf-8"))
        assert config["mcpServers"]["wet-mcp"]["type"] == "http"

    def test_install_opencode(self, installer: AgentInstaller, tmp_path: Path) -> None:
        path = installer.install("opencode")
        assert path == tmp_path / ".config" / "opencode" / "config.json"
        config = json.loads(path.read_text(encoding="utf-8"))
        assert config["mcpServers"]["wet-mcp"]["url"] == "http://127.0.0.1:9876/mcp"


class TestUnsupportedAgents:
    @pytest.mark.parametrize("agent", ["copilot", "antigravity"])
    def test_install_unsupported_raises_notimplemented(self, installer: AgentInstaller, agent: str) -> None:
        with pytest.raises(NotImplementedError, match=agent):
            installer.install(cast(AgentName, agent))

    @pytest.mark.parametrize("agent", ["copilot", "antigravity"])
    def test_uninstall_unsupported_raises_notimplemented(self, installer: AgentInstaller, agent: str) -> None:
        with pytest.raises(NotImplementedError, match=agent):
            installer.uninstall(cast(AgentName, agent))


class TestValidation:
    def test_empty_server_name_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="server_name"):
            AgentInstaller(server_name="", url="http://localhost/mcp", home=tmp_path)

    def test_empty_url_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="url"):
            AgentInstaller(server_name="wet", url="", home=tmp_path)

    def test_supported_agents_constant(self) -> None:
        # Every unsupported agent must NOT be in SUPPORTED_AGENTS.
        for name in UNSUPPORTED_REASON:
            assert name not in SUPPORTED_AGENTS
        # Every supported agent should be expressible through the installer.
        assert set(SUPPORTED_AGENTS) == {
            "claude-code",
            "cursor",
            "codex",
            "windsurf",
            "opencode",
        }

    def test_atomic_write_leaves_no_tmp_file_on_success(self, installer: AgentInstaller, tmp_path: Path) -> None:
        installer.install("claude-code")
        tmp_files = list(tmp_path.glob(".claude.json.*.tmp"))
        assert tmp_files == []
