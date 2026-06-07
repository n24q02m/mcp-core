from pathlib import Path
from unittest.mock import patch

from mcp_core.scripts.clean_state import kill_daemons


def test_kill_daemons_basic(tmp_path: Path):
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir(parents=True)
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(parents=True)

    # Create a lock file
    lock_file = lock_dir / "test-server-123.lock"
    lock_file.write_text("123\n5000\ntoken\n2026-01-01T00:00:00Z\n")

    # Create companion cache file
    cache_file = cache_dir / "test-server-123-http-core.tools.json"
    cache_file.write_text("{}")

    with (
        patch("mcp_core.scripts.clean_state._lock_dir", return_value=lock_dir),
        patch("mcp_core.scripts.clean_state._legacy_posix_base", return_value=tmp_path),
        patch("mcp_core.scripts.clean_state._is_pid_alive") as mock_alive,
        patch("mcp_core.scripts.clean_state._terminate_daemon") as mock_terminate,
        patch("time.sleep"),
    ):
        # Scenario: PID is alive, then dies after one check
        mock_alive.side_effect = [True, False]

        killed, removed = kill_daemons(verbose=True)

        assert killed == 1
        assert removed == 1
        mock_terminate.assert_called_once_with(123)
        assert not lock_file.exists()
        assert not cache_file.exists()


def test_kill_daemons_multiple(tmp_path: Path):
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir(parents=True)

    pids = [101, 102, 103]
    lock_files = []
    for pid in pids:
        lf = lock_dir / f"server-{pid}.lock"
        lf.write_text(f"{pid}\n5000\ntoken\n2026-01-01T00:00:00Z\n")
        lock_files.append(lf)

    with (
        patch("mcp_core.scripts.clean_state._lock_dir", return_value=lock_dir),
        patch("mcp_core.scripts.clean_state._legacy_posix_base", return_value=tmp_path),
        patch("mcp_core.scripts.clean_state._is_pid_alive", return_value=False),
        patch("mcp_core.scripts.clean_state._terminate_daemon"),
        patch("time.sleep"),
    ):
        # All dead initially for simplicity of the "removed" count check
        killed, removed = kill_daemons()

        assert killed == 0
        assert removed == 3
        for lf in lock_files:
            assert not lf.exists()


def test_kill_daemons_alive_and_dies(tmp_path: Path):
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir(parents=True)

    lock_file = lock_dir / "server-999.lock"
    lock_file.write_text("999\n5000\ntoken\n2026-01-01T00:00:00Z\n")

    with (
        patch("mcp_core.scripts.clean_state._lock_dir", return_value=lock_dir),
        patch("mcp_core.scripts.clean_state._legacy_posix_base", return_value=tmp_path),
        patch("mcp_core.scripts.clean_state._is_pid_alive") as mock_alive,
        patch("mcp_core.scripts.clean_state._terminate_daemon"),
        patch("time.sleep") as mock_sleep,
    ):
        # First call to _is_pid_alive in loop: True
        # Second call to _is_pid_alive in loop: False
        # Wait, there is one call before _terminate_daemon too.
        # kill_daemons:
        # if pid is not None and _is_pid_alive(pid):  <-- 1
        #    _terminate_daemon(pid)
        #    for _ in range(20):
        #        if not _is_pid_alive(pid):           <-- 2
        #            break
        #        time.sleep(0.05)

        mock_alive.side_effect = [True, True, False]

        killed, removed = kill_daemons()

        assert killed == 1
        assert mock_alive.call_count == 3
        mock_sleep.assert_called_once()
