from unittest.mock import patch

import pytest

from mcp_core.scripts import clean_state


@pytest.fixture
def mock_env(tmp_path):
    legacy_base = tmp_path / "mcp"
    lock_dir = legacy_base / "locks"
    cache_dir = legacy_base / "cache"
    lock_dir.mkdir(parents=True)
    cache_dir.mkdir(parents=True)

    with patch("mcp_core.scripts.clean_state._legacy_posix_base", return_value=legacy_base):
        yield {"legacy_base": legacy_base, "lock_dir": lock_dir, "cache_dir": cache_dir}


def test_kill_daemons_no_locks(mock_env):
    killed, removed = clean_state.kill_daemons()
    assert killed == 0
    assert removed == 0


def test_kill_daemons_with_alive_process(mock_env):
    lock_dir = mock_env["lock_dir"]
    lock_file = lock_dir / "test.lock"
    # Mock content: PID on line 0
    lock_file.write_text("1234\n9000\ntoken\n2024-01-01\n")

    with (
        patch("mcp_core.scripts.clean_state._is_pid_alive") as mock_is_alive,
        patch("mcp_core.scripts.clean_state._terminate_daemon") as mock_terminate,
        patch("time.sleep") as mock_sleep,
    ):
        # First check: alive. Then dead after terminate.
        mock_is_alive.side_effect = [True, False]

        killed, removed = clean_state.kill_daemons(verbose=True)

        assert killed == 1
        assert removed == 1
        assert not lock_file.exists()
        mock_terminate.assert_called_once_with(1234)
        # Should break loop early if pid not alive
        assert mock_sleep.call_count == 0


def test_kill_daemons_with_reaping_delay(mock_env):
    lock_dir = mock_env["lock_dir"]
    lock_file = lock_dir / "test.lock"
    lock_file.write_text("1234\n")

    with (
        patch("mcp_core.scripts.clean_state._is_pid_alive") as mock_is_alive,
        patch("mcp_core.scripts.clean_state._terminate_daemon"),
        patch("time.sleep") as mock_sleep,
    ):
        # Initial check (True), then 3 loop checks (True, True, False)
        mock_is_alive.side_effect = [True, True, True, False]

        killed, removed = clean_state.kill_daemons()

        assert killed == 1
        assert removed == 1
        assert mock_sleep.call_count == 2


def test_kill_daemons_multiple_locks(mock_env):
    lock_dir = mock_env["lock_dir"]
    lock1 = lock_dir / "test1.lock"
    lock1.write_text("1001\n")
    lock2 = lock_dir / "test2.lock"
    lock2.write_text("1002\n")

    with (
        patch("mcp_core.scripts.clean_state._is_pid_alive") as mock_is_alive,
        patch("mcp_core.scripts.clean_state._terminate_daemon") as mock_terminate,
        patch("time.sleep"),
    ):
        # Each lock gets its own checks
        # Lock 1: alive, then dead
        # Lock 2: alive, then dead
        mock_is_alive.side_effect = [True, False, True, False]

        killed, removed = clean_state.kill_daemons()

        assert killed == 2
        assert removed == 2
        assert not lock1.exists()
        assert not lock2.exists()
        assert mock_terminate.call_count == 2

def test_clean_one_lock_reaping_delay(mock_env):
    lock_dir = mock_env["lock_dir"]
    cache_dir = mock_env["cache_dir"]
    lock_file = lock_dir / "delay.lock"
    lock_file.write_text("5555\n")

    with patch("mcp_core.scripts.clean_state._is_pid_alive") as mock_is_alive,          patch("mcp_core.scripts.clean_state._terminate_daemon"),          patch("time.sleep") as mock_sleep:

        # Initial check (True), then 3 loop checks (True, True, False)
        mock_is_alive.side_effect = [True, True, True, False]

        killed, removed = clean_state._clean_one_lock(lock_file, cache_dir, verbose=False)

        assert killed == 1
        assert removed == 1
        assert mock_sleep.call_count == 2
