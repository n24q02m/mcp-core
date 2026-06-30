import os
import sys
from pathlib import Path
from unittest.mock import patch
import pytest
from mcp_core.lifecycle.lock import LifecycleLock


def test_lock_directory_permissions(tmp_path):
    """Verify that the lock directory is created with restrictive permissions (0o700)."""
    if sys.platform == "win32":
        pytest.skip("Permission bits not applicable on Windows")

    lock_root = tmp_path / "locks"

    # Set a broad umask to see if mkdir honors the mode parameter
    # umask 0 means mkdir(mode=0o777) results in 0o777
    # umask 0 means mkdir(mode=0o700) results in 0o700
    old_umask = os.umask(0)
    try:
        # Mock chmod so we can inspect the directory immediately after mkdir
        with patch.object(Path, "chmod") as mock_chmod:
            _ = LifecycleLock(name="test", port=1234, root=lock_root)

            # Check permissions of the created directory
            stats = lock_root.stat()
            current_mode = stats.st_mode & 0o777

            # If mkdir was called without mode, it defaults to 0o777.
            # With umask 0, it will be 0o777.
            # We want it to be 0o700.
            assert current_mode == 0o700, f"Expected directory to be 0o700 after mkdir, but got {oct(current_mode)}"

            # Also verify chmod was called as a secondary measure
            mock_chmod.assert_called_with(0o700)
    finally:
        os.umask(old_umask)
