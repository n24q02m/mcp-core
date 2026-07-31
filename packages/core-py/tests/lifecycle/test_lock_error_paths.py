"""Tests for error paths in cross-process lifecycle lock."""

import os
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
    """Test that RuntimeError is raised when os.open() fails."""
    lock = LifecycleLock(name="test", port=9000, root=lock_root)
    with patch("os.open", side_effect=OSError("Permission denied")):
        with pytest.raises(RuntimeError, match="Failed to open lock file"):
            with lock:
                pass


def test_fdopen_failure_does_not_leak_the_descriptor(lock_root: Path) -> None:
    """A failure between os.open and os.fdopen must still close the fd.

    ``os.fdopen`` takes ownership of the descriptor only on success; if it
    raises, nothing else will ever close it and the process leaks one per
    attempt.
    """
    lock = LifecycleLock(name="test", port=9000, root=lock_root)
    closed: list[int] = []
    with (
        patch("os.fdopen", side_effect=OSError("no memory")),
        patch("os.close", side_effect=closed.append),
    ):
        with pytest.raises(RuntimeError, match="Failed to open lock file"):
            with lock:
                pass
    assert len(closed) == 1


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
            with (
                patch("os.open", return_value=123),
                patch("os.fdopen", return_value=mock_fh),
            ):
                lock.__enter__()

                # Now set locking to fail for release
                mock_msvcrt.locking.side_effect = OSError("Already unlocked?")

                # Should not raise
                lock.__exit__(None, None, None)

                assert lock._fh is None
                mock_fh.close.assert_called_once()


def test_acquiring_over_a_stale_record_overwrites_it(lock_root: Path) -> None:
    """Re-acquiring must overwrite from offset 0, not append a second record.

    The file was previously opened ``"a+"``, which sets O_APPEND, and under
    O_APPEND every write goes to end-of-file regardless of the ``seek(0)``.
    Acquiring a lock whose file survived an unclean exit therefore left the
    stale record first in the file -- and ``_parse_lock_text`` reads the
    leading four lines, so callers saw a dead PID as the current holder.
    """
    lock = LifecycleLock(name="test", port=9000, root=lock_root)
    stale = "999999\n1234\nstale-token\n2020-01-01T00:00:00+00:00\n".ljust(512, " ")
    lock.path.write_text(stale, encoding="utf-8")

    with lock:
        raw = lock.path.read_text(encoding="utf-8")

    lines = raw.strip().split("\n")
    assert lines[0].strip() == str(os.getpid())
    assert lines[1].strip() == "9000"
    assert "stale-token" not in raw
    assert len(raw) == 512


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_lock_file_is_owner_only_from_creation(lock_root: Path) -> None:
    """The token lives in this file, so it must never exist world-readable.

    Creating with ``open()`` and narrowing with ``chmod`` afterwards leaves a
    window under the process umask; asserting the mode after the fact cannot
    tell the two apart, so this also runs under a permissive umask to prove
    the mode comes from the create call rather than from inherited defaults.
    """
    old_umask = os.umask(0o000)
    try:
        lock = LifecycleLock(name="test", port=9000, root=lock_root)
        with lock:
            mode = lock.path.stat().st_mode & 0o777
    finally:
        os.umask(old_umask)
    assert mode == 0o600
