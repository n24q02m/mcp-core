import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_core.scripts.clean_state import (
    _enumerate,
    kill_daemons,
    main,
    _parse_lock_pid,
    _is_pid_alive,
    _confirm,
)


@pytest.fixture
def mock_fs(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()

    config_dir = tmp_path / "config"
    config_dir.mkdir()

    legacy_dir = home / ".config" / "mcp"
    legacy_dir.mkdir(parents=True)

    monkeypatch.setattr("mcp_core.scripts.clean_state._home", lambda: home)
    monkeypatch.setattr("mcp_core.scripts.clean_state._python_config_base", lambda: config_dir)
    monkeypatch.setattr("mcp_core.scripts.clean_state._legacy_posix_base", lambda: legacy_dir)
    monkeypatch.setattr("mcp_core.scripts.clean_state._ts_config_base", lambda: None)

    return {
        "home": home,
        "config": config_dir,
        "legacy": legacy_dir,
    }


def test_parse_lock_pid(tmp_path):
    lock_file = tmp_path / "test.lock"

    # Valid PID
    lock_file.write_text("1234\nport\ntoken\ndate")
    assert _parse_lock_pid(lock_file) == 1234

    # Invalid PID (not an int)
    lock_file.write_text("abc\nport")
    assert _parse_lock_pid(lock_file) is None

    # Missing file
    assert _parse_lock_pid(tmp_path / "missing.lock") is None

    # Empty file
    lock_file.write_text("")
    assert _parse_lock_pid(lock_file) is None

    # Zero or negative PID
    lock_file.write_text("0")
    assert _parse_lock_pid(lock_file) is None


def test_is_pid_alive_posix(monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX only")

    def mock_kill(pid, sig):
        if pid == 1234:
            return
        raise OSError(3, "No such process")

    monkeypatch.setattr(os, "kill", mock_kill)

    assert _is_pid_alive(1234) is True
    assert _is_pid_alive(5678) is False
    assert _is_pid_alive(0) is False


def test_enumerate_basic(mock_fs):
    # Setup some paths
    (mock_fs["config"] / "config.enc").write_text("dummy")

    locks = mock_fs["legacy"] / "locks"
    locks.mkdir()
    (locks / "test.lock").write_text("123")

    cache = mock_fs["legacy"] / "cache"
    cache.mkdir()
    (cache / "test.tools.json").write_text("{}")

    # Per-server paths
    server_dir = mock_fs["home"] / ".wet-mcp"
    server_dir.mkdir()
    (server_dir / "tokens").mkdir()
    (server_dir / "tokens" / "token1").write_text("abc")

    paths = _enumerate(["wet-mcp"], keep_data=True)

    path_names = [p.name for p in paths]
    assert "config.enc" in path_names
    assert "test.lock" in path_names
    assert "test.tools.json" in path_names
    assert "token1" in path_names
    assert "data" not in path_names


def test_enumerate_with_data(mock_fs):
    server_dir = mock_fs["home"] / ".wet-mcp"
    server_dir.mkdir()
    data_dir = server_dir / "data"
    data_dir.mkdir()

    paths = _enumerate(["wet-mcp"], keep_data=False)
    path_names = [p.name for p in paths]
    assert "data" in path_names


def test_enumerate_imagine_mcp(mock_fs):
    server_dir = mock_fs["home"] / ".imagine-mcp"
    server_dir.mkdir()

    cache_dir = server_dir / "cache"
    cache_dir.mkdir()
    (cache_dir / "item1").write_text("data")

    diskcache_dir = server_dir / "diskcache"
    diskcache_dir.mkdir()

    paths = _enumerate(["imagine-mcp"], keep_data=False)
    path_names = [p.name for p in paths]
    assert "item1" in path_names
    assert "diskcache" in path_names


def test_enumerate_duplicate_and_error(mock_fs, monkeypatch):
    (mock_fs["config"] / "config.enc").write_text("dummy")

    # Mock resolve to return duplicate or raise OSError
    original_resolve = Path.resolve

    def mock_resolve(self):
        if self.name == "config.enc":
            raise OSError("mock error")
        return original_resolve(self)

    monkeypatch.setattr(Path, "resolve", mock_resolve)

    paths = _enumerate(["wet-mcp"], keep_data=True)
    assert any(p.name == "config.enc" for p in paths)


def test_confirm_auto_yes(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert _confirm() is True


def test_kill_daemons_missing_dir(mock_fs, capsys):
    # delete legacy dir
    shutil.rmtree(mock_fs["legacy"])
    res = kill_daemons()
    assert res == (0, 0)
    assert "No lock directory" in capsys.readouterr().out


def test_kill_daemons_no_locks(mock_fs, capsys):
    (mock_fs["legacy"] / "locks").mkdir()
    res = kill_daemons()
    assert res == (0, 0)
    assert "No lock files" in capsys.readouterr().out


def test_kill_daemons_errors(mock_fs, monkeypatch, capsys):
    locks_dir = mock_fs["legacy"] / "locks"
    locks_dir.mkdir()
    lock_file = locks_dir / "err.lock"
    lock_file.write_text("1234")

    cache_dir = mock_fs["legacy"] / "cache"
    cache_dir.mkdir()
    cache_file = cache_dir / "err-1234-.tools.json"
    cache_file.write_text("{}")

    sentinel_file = locks_dir / "err.lock.tools-list-changed"
    sentinel_file.write_text("changed")

    monkeypatch.setattr("mcp_core.scripts.clean_state._is_pid_alive", lambda pid: False)

    def mock_unlink(self):
        raise OSError("unlink failed")

    monkeypatch.setattr(Path, "unlink", mock_unlink)

    kill_daemons(verbose=True)
    captured = capsys.readouterr()
    assert "failed to remove" in captured.err


def test_main_success_verbose(mock_fs, monkeypatch, capsys):
    cfg_file = mock_fs["config"] / "config.enc"
    cfg_file.write_text("dummy")
    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp"])

    # Mock non-interactive
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    exit_code = main(["--server", "wet-mcp", "--verbose"])

    assert exit_code == 0
    assert not cfg_file.exists()
    captured = capsys.readouterr()
    assert "removed:" in captured.out


def test_main_rmtree_error(mock_fs, monkeypatch, capsys):
    server_dir = mock_fs["home"] / ".wet-mcp"
    server_dir.mkdir()
    data_dir = server_dir / "data"
    data_dir.mkdir()

    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    def mock_rmtree(p):
        raise OSError("rmtree error")

    monkeypatch.setattr(shutil, "rmtree", mock_rmtree)

    exit_code = main(["--no-keep-data", "--server", "wet-mcp"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "failed:" in captured.err


def test_kill_daemons_real_scenario(mock_fs, monkeypatch):
    locks_dir = mock_fs["legacy"] / "locks"
    locks_dir.mkdir()

    lock_file = locks_dir / "srv-1234.lock"
    lock_file.write_text("1234")

    # Mock process liveness and termination
    # First call to _is_pid_alive returns True, second returns False to break the wait loop
    alive_states = [True, True, False]

    def mock_is_alive(pid):
        if pid == 1234 and alive_states:
            return alive_states.pop(0)
        return False

    monkeypatch.setattr("mcp_core.scripts.clean_state._is_pid_alive", mock_is_alive)
    mock_terminate = MagicMock()
    monkeypatch.setattr("mcp_core.scripts.clean_state._terminate_daemon", mock_terminate)
    monkeypatch.setattr("time.sleep", lambda x: None)

    killed, removed = kill_daemons(verbose=True)

    assert killed == 1
    assert removed == 1
    mock_terminate.assert_called_once_with(1234)
    assert not lock_file.exists()


def test_main_dry_run(mock_fs, monkeypatch, capsys):
    (mock_fs["config"] / "config.enc").write_text("dummy")
    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp"])

    exit_code = main(["--dry-run", "--server", "wet-mcp"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "[dry-run] Would remove" in captured.out
    assert "config.enc" in captured.out
    assert (mock_fs["config"] / "config.enc").exists()


def test_main_abort(mock_fs, monkeypatch, capsys):
    (mock_fs["config"] / "config.enc").write_text("dummy")
    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp"])

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdin.readline", lambda: "n\n")

    exit_code = main(["--server", "wet-mcp"])

    assert exit_code == 1
    assert (mock_fs["config"] / "config.enc").exists()


def test_main_kill_daemons_flag(monkeypatch):
    mock_kill = MagicMock(return_value=(1, 2))
    monkeypatch.setattr("mcp_core.scripts.clean_state.kill_daemons", mock_kill)

    exit_code = main(["--kill-daemons"])

    assert exit_code == 0
    mock_kill.assert_called_once()


def test_main_unknown_server(capsys):
    exit_code = main(["--server", "unknown-server"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "unknown server" in captured.err


def test_main_no_paths_found(mock_fs, monkeypatch, capsys):
    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp"])
    exit_code = main(["--server", "wet-mcp"])
    assert exit_code == 0
    assert "Nothing to clean." in capsys.readouterr().out


def test_ts_config_base_nt_mock(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(os.environ, "get", lambda k, d=None: str(tmp_path) if k == "APPDATA" else d)

    with patch("mcp_core.scripts.clean_state.Path") as mock_path:
        from mcp_core.scripts.clean_state import _ts_config_base

        _ts_config_base()
        mock_path.assert_called()


def test_home_and_python_config_base():
    from mcp_core.scripts.clean_state import _home, _python_config_base

    assert isinstance(_home(), Path)
    assert isinstance(_python_config_base(), Path)
