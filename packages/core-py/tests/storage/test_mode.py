"""Tests for server mode management."""

import pytest

from mcp_core.storage.config_file import (
    read_config,
    set_config_path,
    write_config,
)
from mcp_core.storage.mode import clear_mode, get_mode, set_local_mode


@pytest.fixture(autouse=True)
def _temp_config(tmp_path):
    config_path = str(tmp_path / "config.enc")
    set_config_path(config_path)
    yield
    set_config_path(None)


class TestSetLocalMode:
    def test_writes_mode_marker(self):
        set_local_mode("test-server")

        config = read_config("test-server")
        assert config is not None
        assert config["_mode"] == "local"

    def test_overwrites_existing_config(self):
        write_config("test-server", {"api_key": "secret123"})
        set_local_mode("test-server")

        config = read_config("test-server")
        assert config == {"_mode": "local"}


class TestGetMode:
    def test_returns_none_when_no_config(self):
        result = get_mode("test-server")
        assert result is None

    def test_returns_local_when_local_mode_set(self):
        set_local_mode("test-server")
        result = get_mode("test-server")
        assert result == "local"

    def test_returns_configured_when_has_real_keys(self):
        write_config("test-server", {"api_key": "key123", "base_url": "https://api"})
        result = get_mode("test-server")
        assert result == "configured"

    def test_returns_configured_with_mixed_keys(self):
        write_config("test-server", {"_mode": "something-else", "api_key": "key123"})
        result = get_mode("test-server")
        assert result == "configured"

    def test_returns_none_with_empty_mode_value(self):
        write_config("test-server", {"_mode": "unknown"})
        result = get_mode("test-server")
        # Has _mode but not "local", and no other keys
        assert result is None


class TestClearMode:
    def test_removes_config_entry(self):
        set_local_mode("test-server")
        assert get_mode("test-server") == "local"

        clear_mode("test-server")
        assert get_mode("test-server") is None

    def test_removes_configured_entry(self):
        write_config("test-server", {"api_key": "key123"})
        assert get_mode("test-server") == "configured"

        clear_mode("test-server")
        assert get_mode("test-server") is None

    def test_no_error_when_no_config(self):
        # Should not raise
        clear_mode("nonexistent-server")


class TestModeIndependence:
    def test_different_servers_have_independent_modes(self):
        set_local_mode("server-a")
        write_config("server-b", {"api_key": "key"})

        assert get_mode("server-a") == "local"
        assert get_mode("server-b") == "configured"
        assert get_mode("server-c") is None

    def test_clearing_one_server_does_not_affect_others(self):
        set_local_mode("server-a")
        set_local_mode("server-b")

        clear_mode("server-a")

        assert get_mode("server-a") is None
        assert get_mode("server-b") == "local"
