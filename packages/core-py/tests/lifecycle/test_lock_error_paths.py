"""Tests for error paths in cross-process lifecycle lock."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_core.lifecycle.lock import LifecycleLock


@pytest.fixture
def lock_root(tmp_path: Path) -> Path:
    """Per-test lock directory."""
    root = tmp_path / "locks"
    root.mkdir(parents=True, exist_ok=True)
    return root


def test_open_fails(lock_root: Path) -> None:
    """Test that RuntimeError is raised when open() fails."""
    lock = LifecycleLock(name="test", port=9000, root=lock_root)
    with patch("builtins.open", side_effect=OSError("Permission denied")):
        with pytest.raises(RuntimeError, match="Failed to open lock file"):
            with lock:
                pass


def test_unlink_fails(lock_root: Path) -> None:
    """Test that OSError during unlink() is caught and ignored."""
    lock = LifecycleLock(name="test", port=9000, root=lock_root)
    with lock:
        # Mock unlink to fail
        with patch("pathlib.Path.unlink", side_effect=OSError("Device busy")):
            # Should not raise
            lock.__exit__(None, None, None)

    # Ensure it's None now
    assert lock._fh is None


def test_windows_acquire_contention(lock_root: Path) -> None:
    """Test Windows-specific contention path."""
    lock = LifecycleLock(name="test", port=9000, root=lock_root)

    # Mock sys.platform to win32
    with patch("sys.platform", "win32"):
        # We need to mock msvcrt because it won't be importable on Linux
        mock_msvcrt = MagicMock()
        mock_msvcrt.LK_NBLCK = 1
        mock_msvcrt.locking.side_effect = OSError("Lock violation")

        with patch.dict("sys.modules", {"msvcrt": mock_msvcrt}):
            with pytest.raises(RuntimeError, match="another process holds"):
                with lock:
                    pass

            assert lock._fh is None


def test_windows_release_ignores_oserror(lock_root: Path) -> None:
    """Test that Windows release ignores OSError during unlocking."""
    lock = LifecycleLock(name="test", port=9000, root=lock_root)

    # Mock sys.platform to win32 for the whole sequence
    with patch("sys.platform", "win32"):
        mock_msvcrt = MagicMock()
        mock_msvcrt.LK_NBLCK = 1
        mock_msvcrt.LK_UNLCK = 2

        with patch.dict("sys.modules", {"msvcrt": mock_msvcrt}):
            # Successfully "acquire"
            # We need to mock open to return a mock file handle that doesn't actually call msvcrt
            mock_fh = MagicMock()
            with patch("builtins.open", return_value=mock_fh):
                lock.__enter__()

                # Now set locking to fail for release
                mock_msvcrt.locking.side_effect = OSError("Already unlocked?")

                # Should not raise
                lock.__exit__(None, None, None)

                assert lock._fh is None
                mock_fh.close.assert_called_once()
