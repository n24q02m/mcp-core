import os
import shutil
import sys
from pathlib import Path, PureWindowsPath
from unittest.mock import MagicMock, patch

import pytest
from mcp_core.scripts import clean_state


@pytest.fixture
def mock_fs(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    config = tmp_path / "config"
    config.mkdir()

    legacy_base = home / ".config" / "mcp"
    legacy_base.mkdir(parents=True)

    # We mock these to point to our tmp_path
    with (
        patch("mcp_core.scripts.clean_state._home", return_value=home),
        patch("mcp_core.scripts.clean_state._python_config_base", return_value=config),
        patch("mcp_core.scripts.clean_state._ts_config_base", return_value=None),
        patch("mcp_core.scripts.clean_state._legacy_posix_base", return_value=legacy_base),
    ):
        yield {
            "home": home,
            "config": config,
            "legacy": legacy_base,
        }


def test_home():
    with patch("pathlib.Path.home", return_value=Path("/fake/home")):
        assert clean_state._home() == Path("/fake/home")


def test_python_config_base():
    with patch("mcp_core.scripts.clean_state.user_config_dir", return_value="/fake/config"):
        assert clean_state._python_config_base() == Path("/fake/config")


def test_ts_config_base_posix():
    with patch("os.name", "posix"):
        assert clean_state._ts_config_base() is None


def test_ts_config_base_nt():
    with (
        patch("os.name", "nt"),
        patch.dict(os.environ, {"APPDATA": "C:\\AppData"}),
        patch("mcp_core.scripts.clean_state.Path", PureWindowsPath),
    ):
        assert clean_state._ts_config_base() == PureWindowsPath("C:\\AppData") / "mcp" / "Config"


def test_ts_config_base_nt_no_appdata():
    with patch("os.name", "nt"), patch.dict(os.environ, {}, clear=True):
        assert clean_state._ts_config_base() is None


def test_legacy_posix_base():
    with patch("mcp_core.scripts.clean_state._home", return_value=Path("/fake/home")):
        # Call the real function
        assert clean_state._legacy_posix_base() == Path("/fake/home") / ".config" / "mcp"


def test_enumerate_basic(mock_fs):
    home = mock_fs["home"]
    config = mock_fs["config"]
    legacy = mock_fs["legacy"]

    # Create config file
    cfg_file = config / "config.enc"
    cfg_file.write_text("dummy")

    # Create legacy locks and cache
    locks_dir = legacy / "locks"
    locks_dir.mkdir()
    lock_file = locks_dir / "test.lock"
    lock_file.write_text("dummy")

    cache_dir = legacy / "cache"
    cache_dir.mkdir()
    cache_file = cache_dir / "test.tools.json"
    cache_file.write_text("dummy")

    # Create server token and session
    wet_mcp_home = home / ".wet-mcp"
    wet_mcp_home.mkdir()
    tokens_dir = wet_mcp_home / "tokens"
    tokens_dir.mkdir()
    token_file = tokens_dir / "token.json"
    token_file.write_text("dummy")

    sessions_dir = wet_mcp_home / "sessions"
    sessions_dir.mkdir()
    session_file = sessions_dir / "test.session"
    session_file.write_text("dummy")

    paths = clean_state._enumerate(["wet-mcp"], keep_data=True)
    assert cfg_file in paths
    assert lock_file in paths
    assert cache_file in paths
    assert token_file in paths
    assert session_file in paths


def test_enumerate_duplicate_paths(mock_fs):
    config = mock_fs["config"]
    cfg_file = config / "config.enc"
    cfg_file.write_text("dummy")

    with patch("mcp_core.scripts.clean_state._legacy_posix_base", return_value=config):
        paths = clean_state._enumerate([], keep_data=True)
        # Should only have one cfg_file even if multiple bases point to it
        assert paths.count(cfg_file) == 1


def test_enumerate_resolve_error(mock_fs):
    config = mock_fs["config"]
    cfg_file = config / "config.enc"
    cfg_file.write_text("dummy")

    with patch.object(Path, "resolve", side_effect=OSError):
        paths = clean_state._enumerate([], keep_data=True)
        assert cfg_file in paths


def test_enumerate_keep_data(mock_fs):
    home = mock_fs["home"]
    wet_mcp_home = home / ".wet-mcp"
    wet_mcp_home.mkdir()
    data_dir = wet_mcp_home / "data"
    data_dir.mkdir()

    # With keep_data=True (default)
    paths = clean_state._enumerate(["wet-mcp"], keep_data=True)
    assert data_dir not in paths

    # With keep_data=False
    paths = clean_state._enumerate(["wet-mcp"], keep_data=False)
    assert data_dir in paths


def test_enumerate_imagine_mcp_special(mock_fs):
    home = mock_fs["home"]
    imagine_home = home / ".imagine-mcp"
    imagine_home.mkdir()
    cache_dir = imagine_home / "cache"
    cache_dir.mkdir()
    cache_file = cache_dir / "img.png"
    cache_file.write_text("data")

    diskcache_dir = imagine_home / "diskcache"
    diskcache_dir.mkdir()

    # Tokens and cache
    paths = clean_state._enumerate(["imagine-mcp"], keep_data=True)
    assert cache_file in paths
    assert diskcache_dir not in paths

    # With data
    paths = clean_state._enumerate(["imagine-mcp"], keep_data=False)
    assert diskcache_dir in paths


def test_per_server_paths_no_base(mock_fs):
    # Base doesn't exist
    assert clean_state._per_server_token_paths("nonexistent") == []
    assert clean_state._per_server_data_paths("nonexistent") == []


def test_main_dry_run(mock_fs, capsys):
    config = mock_fs["config"]
    cfg_file = config / "config.enc"
    cfg_file.write_text("dummy")

    exit_code = clean_state.main(["--dry-run", "--server", "wet-mcp"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "[dry-run] Would remove" in captured.out
    assert "config.enc" in captured.out
    assert cfg_file.exists()


def test_main_cleanup(mock_fs, capsys):
    config = mock_fs["config"]
    cfg_file = config / "config.enc"
    cfg_file.write_text("dummy")

    # Add a directory to test rmtree
    home = mock_fs["home"]
    wet_mcp_home = home / ".wet-mcp"
    wet_mcp_home.mkdir()
    data_dir = wet_mcp_home / "data"
    data_dir.mkdir()

    with patch("mcp_core.scripts.clean_state._confirm", return_value=True):
        exit_code = clean_state.main(["--server", "wet-mcp", "--no-keep-data", "--verbose"])

    assert exit_code == 0
    assert not cfg_file.exists()
    assert not data_dir.exists()
    captured = capsys.readouterr()
    assert "Removed 2/2 path(s)" in captured.out
    assert "removed:" in captured.out


def test_main_cleanup_error(mock_fs, capsys):
    config = mock_fs["config"]
    cfg_file = config / "config.enc"
    cfg_file.write_text("dummy")

    with (
        patch("mcp_core.scripts.clean_state._confirm", return_value=True),
        patch.object(Path, "unlink", side_effect=OSError("perm error")),
    ):
        exit_code = clean_state.main(["--server", "wet-mcp"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "failed:" in captured.err
    assert "perm error" in captured.err


def test_main_confirm_abort(mock_fs, capsys):
    config = mock_fs["config"]
    cfg_file = config / "config.enc"
    cfg_file.write_text("dummy")

    with patch("mcp_core.scripts.clean_state._confirm", return_value=False):
        exit_code = clean_state.main(["--server", "wet-mcp"])

    assert exit_code == 1
    assert cfg_file.exists()
    captured = capsys.readouterr()
    assert "Aborted." in captured.out


def test_parse_lock_pid(tmp_path):
    lock = tmp_path / "test.lock"

    # Valid
    lock.write_text("1234\n")
    assert clean_state._parse_lock_pid(lock) == 1234

    # Empty
    lock.write_text("")
    assert clean_state._parse_lock_pid(lock) is None

    # Invalid int
    lock.write_text("abc\n")
    assert clean_state._parse_lock_pid(lock) is None

    # Non-positive
    lock.write_text("0\n")
    assert clean_state._parse_lock_pid(lock) is None

    # Missing file
    assert clean_state._parse_lock_pid(tmp_path / "missing") is None


def test_is_pid_alive_posix():
    with patch("os.name", "posix"), patch("os.kill") as mock_kill:
        assert clean_state._is_pid_alive(1234) is True
        mock_kill.assert_called_with(1234, 0)

        mock_kill.side_effect = OSError()
        assert clean_state._is_pid_alive(1234) is False

        mock_kill.side_effect = PermissionError()
        assert clean_state._is_pid_alive(1234) is False

    assert clean_state._is_pid_alive(0) is False


def test_is_pid_alive_nt():
    mock_ctypes = MagicMock()
    with patch("os.name", "nt"), patch.dict(sys.modules, {"ctypes": mock_ctypes}):
        mock_ctypes.windll.kernel32.OpenProcess.return_value = 1
        assert clean_state._is_pid_alive(1234) is True

        mock_ctypes.windll.kernel32.OpenProcess.return_value = 0
        assert clean_state._is_pid_alive(1234) is False


def test_terminate_daemon_posix():
    with patch("os.name", "posix"), patch("os.kill") as mock_kill:
        import signal

        clean_state._terminate_daemon(1234)
        mock_kill.assert_called_with(1234, signal.SIGKILL)

        mock_kill.side_effect = OSError()
        clean_state._terminate_daemon(1234)  # should not raise

    clean_state._terminate_daemon(0)  # no-op


def test_terminate_daemon_nt():
    mock_ctypes = MagicMock()
    with patch("os.name", "nt"), patch.dict(sys.modules, {"ctypes": mock_ctypes}):
        mock_ctypes.windll.kernel32.OpenProcess.return_value = 1
        clean_state._terminate_daemon(1234)
        mock_ctypes.windll.kernel32.TerminateProcess.assert_called_once()


def test_kill_daemons(mock_fs, capsys):
    legacy = mock_fs["legacy"]
    locks_dir = legacy / "locks"
    locks_dir.mkdir()
    cache_dir = legacy / "cache"
    cache_dir.mkdir()

    lock_file = locks_dir / "wet-mcp.lock"
    lock_file.write_text("1234\n8080\ntoken\n2024-01-01\n")

    cache_file = cache_dir / "wet-mcp-1234-http-core.tools.json"
    cache_file.write_text("{}")

    # Sibling sentinel
    sentinel = locks_dir / "wet-mcp.lock.tools-list-changed"
    sentinel.write_text("changed")

    # Test wait loop by having it alive once then dead
    with (
        patch("mcp_core.scripts.clean_state._is_pid_alive", side_effect=[True, True, False]),
        patch("mcp_core.scripts.clean_state._terminate_daemon") as mock_term,
        patch("time.sleep"),
    ):
        killed, removed = clean_state.kill_daemons(verbose=True)

    assert killed == 1
    assert removed == 1
    mock_term.assert_called_once_with(1234)
    assert not lock_file.exists()
    assert not cache_file.exists()
    assert not sentinel.exists()


def test_kill_daemons_no_dir(mock_fs, capsys):
    legacy = mock_fs["legacy"]
    shutil.rmtree(legacy)

    killed, removed = clean_state.kill_daemons()
    assert killed == 0
    assert removed == 0
    captured = capsys.readouterr()
    assert "No lock directory" in captured.out


def test_kill_daemons_no_locks(mock_fs, capsys):
    legacy = mock_fs["legacy"]
    (legacy / "locks").mkdir()

    killed, removed = clean_state.kill_daemons()
    assert killed == 0
    assert removed == 0
    captured = capsys.readouterr()
    assert "No lock files" in captured.out


def test_kill_daemons_errors(mock_fs, capsys):
    legacy = mock_fs["legacy"]
    locks_dir = legacy / "locks"
    locks_dir.mkdir()
    cache_dir = legacy / "cache"
    cache_dir.mkdir()

    lock_file = locks_dir / "wet-mcp.lock"
    lock_file.write_text("1234\n")

    cache_file = cache_dir / "wet-mcp-1234-x.tools.json"
    cache_file.write_text("{}")

    sentinel = locks_dir / "wet-mcp.lock.tools-list-changed"
    sentinel.write_text("x")

    with (
        patch("mcp_core.scripts.clean_state._is_pid_alive", return_value=False),
        patch.object(Path, "unlink", side_effect=OSError("unlink error")),
    ):
        killed, removed = clean_state.kill_daemons()

    assert killed == 0
    assert removed == 0
    captured = capsys.readouterr()
    assert "failed to remove" in captured.err


def test_main_kill_daemons_flag(mock_fs):
    with patch("mcp_core.scripts.clean_state.kill_daemons") as mock_kill:
        exit_code = clean_state.main(["--kill-daemons"])
        assert exit_code == 0
        mock_kill.assert_called_once()


def test_main_unknown_server(mock_fs, capsys):
    exit_code = clean_state.main(["--server", "unknown-mcp"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "unknown server" in captured.err


def test_main_nothing_to_clean(mock_fs, capsys):
    exit_code = clean_state.main(["--server", "wet-mcp"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Nothing to clean." in captured.out


def test_confirm_non_tty():
    with patch("sys.stdin.isatty", return_value=False):
        assert clean_state._confirm() is True


def test_confirm_tty(monkeypatch):
    with patch("sys.stdin.isatty", return_value=True):
        monkeypatch.setattr("sys.stdin.readline", lambda: "y\n")
        assert clean_state._confirm() is True

        monkeypatch.setattr("sys.stdin.readline", lambda: "n\n")
        assert clean_state._confirm() is False
