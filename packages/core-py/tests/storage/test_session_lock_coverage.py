"""Additional tests for file-based session lock to increase coverage."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_core.storage.session_lock import (
    _get_lock_dir,
    acquire_session_lock,
    release_session_lock,
    set_lock_dir,
)


@pytest.fixture(autouse=True)
def _reset_lock_dir():
    set_lock_dir(None)
    yield
    set_lock_dir(None)


def test_get_lock_dir_default():
    """Test _get_lock_dir when no override is set (line 37)."""
    # Ensure it's None first
    set_lock_dir(None)
    result = _get_lock_dir()
    assert isinstance(result, Path)


@pytest.mark.asyncio
async def test_release_session_lock_os_error(tmp_path):
    """Test release_session_lock when unlink raises OSError (lines 149-150)."""
    set_lock_dir(str(tmp_path))

    # We need to patch Path.unlink specifically for the lock path
    with patch("pathlib.Path.unlink", side_effect=OSError("Mocked unlink error")):
        # This should not raise but log the error
        await release_session_lock("test-server")


@pytest.mark.asyncio
async def test_acquire_session_lock_corrupt_nested_os_error(tmp_path):
    """Test acquire_session_lock recovery when release also fails (lines 106-107)."""
    set_lock_dir(str(tmp_path))

    # Create a lock file so path.exists() returns True
    lock_file = tmp_path / "relay-session-test-server.lock"
    lock_file.write_text("corrupt content", encoding="utf-8")

    # Mock Path.read_text to trigger the outer catch
    # AND mock release_session_lock to raise OSError to trigger the inner catch
    with (
        patch("pathlib.Path.read_text", side_effect=json.JSONDecodeError("Mocked json error", "", 0)),
        patch("mcp_core.storage.session_lock.release_session_lock", side_effect=OSError("Mocked release error")),
    ):
        result = await acquire_session_lock("test-server")
        assert result is None
