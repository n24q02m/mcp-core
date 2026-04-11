"""Tests for config resolution."""

import os

import pytest

from mcp_core.storage.config_file import set_config_path, write_config
from mcp_core.storage.resolver import resolve_config


@pytest.fixture(autouse=True)
def _temp_config(tmp_path):
    config_path = str(tmp_path / "config.enc")
    set_config_path(config_path)
    yield
    set_config_path(None)
    # Clean env vars
    for key in list(os.environ.keys()):
        if key.startswith("MCP_"):
            del os.environ[key]


class TestResolveConfig:
    def test_env_vars_take_highest_priority(self):
        os.environ["MCP_TELEGRAM_BOT_TOKEN"] = "env-token"
        os.environ["MCP_TELEGRAM_CHAT_ID"] = "env-chat"

        # Also write to config file (should be ignored)
        write_config("telegram", {"bot_token": "file-token", "chat_id": "file-chat"})

        result = resolve_config("telegram", ["bot_token", "chat_id"])
        assert result.source == "env"
        assert result.config == {"bot_token": "env-token", "chat_id": "env-chat"}

    def test_falls_back_to_config_file_when_env_incomplete(self):
        os.environ["MCP_TELEGRAM_BOT_TOKEN"] = "env-token"
        # chat_id NOT set in env

        write_config("telegram", {"bot_token": "file-token", "chat_id": "file-chat"})

        result = resolve_config("telegram", ["bot_token", "chat_id"])
        assert result.source == "file"
        assert result.config == {"bot_token": "file-token", "chat_id": "file-chat"}

    def test_falls_back_to_defaults_when_file_incomplete(self):
        write_config("telegram", {"bot_token": "file-token"})
        # file missing chat_id

        defaults = {"bot_token": "def-token", "chat_id": "def-chat"}
        result = resolve_config("telegram", ["bot_token", "chat_id"], defaults)
        assert result.source == "defaults"
        assert result.config == defaults

    def test_returns_none_when_nothing_found(self):
        result = resolve_config("telegram", ["bot_token", "chat_id"])
        assert result.source is None
        assert result.config is None

    def test_returns_none_when_defaults_incomplete(self):
        result = resolve_config("telegram", ["bot_token", "chat_id"], {"bot_token": "partial"})
        assert result.source is None
        assert result.config is None

    def test_handles_hyphenated_server_names(self):
        os.environ["MCP_MY_SERVER_API_KEY"] = "key123"

        result = resolve_config("my-server", ["api_key"])
        assert result.source == "env"
        assert result.config == {"api_key": "key123"}

    def test_empty_env_var_is_treated_as_missing(self):
        os.environ["MCP_TELEGRAM_BOT_TOKEN"] = ""

        result = resolve_config("telegram", ["bot_token"])
        assert result.source is None
        assert result.config is None

    def test_file_config_with_empty_value_is_treated_as_missing(self):
        write_config("telegram", {"bot_token": ""})

        result = resolve_config("telegram", ["bot_token"])
        assert result.source is None
        assert result.config is None
