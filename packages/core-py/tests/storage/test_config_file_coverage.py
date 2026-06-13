import os
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_core.storage.config_file import (
    SETUP_COMPLETE_KEY,
    _get_config_path,
    clear_key_cache_for_testing,
    mark_setup_complete,
    read_config,
    schedule_reload_exit,
    set_config_path,
    write_config,
)


@pytest.fixture
def _temp_config(tmp_path):
    config_path = str(tmp_path / "config.enc")
    set_config_path(config_path)
    clear_key_cache_for_testing()
    yield tmp_path
    set_config_path(None)
    clear_key_cache_for_testing()


def test_get_config_path_default():
    set_config_path(None)
    path = _get_config_path()
    assert isinstance(path, Path)


def test_mark_setup_complete(_temp_config):
    server_name = "test-server"
    mark_setup_complete(server_name)
    config = read_config(server_name)
    assert config == {SETUP_COMPLETE_KEY: "true"}


def test_load_store_all_fail(_temp_config):
    config_path = _temp_config / "config.enc"
    config_path.write_bytes(b"garbage-that-fails-all-formats")

    # This should hit the last raise err from None
    with pytest.raises(Exception):
        read_config("anything")


def test_save_store_retries(_temp_config):
    # Mocking write_bytes to fail twice with EAGAIN/EBUSY and then succeed.
    # We must also mock os.chmod because write_bytes doesn't actually write a file when mocked.
    with patch("pathlib.Path.write_bytes") as mock_write_bytes:
        mock_write_bytes.side_effect = [OSError(11, "EAGAIN"), OSError(16, "EBUSY"), None]

        with patch("os.chmod") as mock_chmod, patch("time.sleep") as mock_sleep:
            write_config("test", {"k": "v"})

            assert mock_write_bytes.call_count == 3
            assert mock_sleep.call_count == 2
            assert mock_chmod.called


def test_schedule_reload_exit():
    # Force PYTEST_CURRENT_TEST to be absent to enter the block
    with patch.dict(os.environ, {}, clear=True):
        # Verify it's absent
        assert "PYTEST_CURRENT_TEST" not in os.environ
        with patch("threading.Thread") as mock_thread, patch("time.sleep") as mock_sleep:
            schedule_reload_exit()
            assert mock_thread.called

            # To hit the code inside _exit, we need to extract and call it
            exit_fn = mock_thread.call_args[1]["target"]

            with patch("os._exit") as mock_os_exit:
                exit_fn()
                assert mock_sleep.called
                assert mock_os_exit.called
                mock_os_exit.assert_called_with(0)

    # Test with MCP_NO_RELOAD
    with patch.dict(os.environ, {"MCP_NO_RELOAD": "1"}, clear=True):
        with patch("threading.Thread") as mock_thread:
            schedule_reload_exit()
            assert not mock_thread.called
