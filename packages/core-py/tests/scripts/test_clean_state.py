import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_core.scripts.clean_state import (
    ALL_SERVERS,
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


def test_all_servers_matches_canonical_mcp_server_scope():
    assert len(ALL_SERVERS) == 9
    assert set(ALL_SERVERS) == {
        "better-notion-mcp",
        "better-email-mcp",
        "better-telegram-mcp",
        "better-godot-mcp",
        "better-workspace-mcp",
        "wet-mcp",
        "mnemo-mcp",
        "better-code-review-graph",
        "imagine-mcp",
    }


def test_main_default_wipes_workspace_credentials_but_keeps_data(mock_fs):
    server_dir = mock_fs["home"] / ".better-workspace-mcp"
    sub_dir = server_dir / "subs" / "user-a"
    token_dir = sub_dir / "tokens"
    data_dir = server_dir / "data"
    token_dir.mkdir(parents=True)
    data_dir.mkdir(parents=True)

    config = server_dir / "config.json"
    secret = server_dir / ".secret"
    sub_config = sub_dir / "config.json"
    token = token_dir / "google.json"
    sentinel = data_dir / "keep.db"
    config.write_text("{}")
    secret.write_bytes(b"synthetic-key")
    sub_config.write_text("{}")
    token.write_text("{}")
    sentinel.write_text("synthetic-app-data")

    exit_code = main(["--yes"])

    assert exit_code == 0
    assert not config.exists()
    assert not secret.exists()
    assert not (server_dir / "subs").exists()
    assert sentinel.read_text() == "synthetic-app-data"


def test_help_reports_all_nine_servers(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    assert "Default: all 9." in capsys.readouterr().out


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


def test_enumerate_wipes_per_plugin_store_config_and_secret(mock_fs):
    """PerPluginStore (mcp_core.storage.per_plugin_store) writes config.json +
    a machine-bound .secret key at ~/.<server>/ for single-user mode. Clean
    state must wipe both, else E2E runs against credentials that survived
    the "clean" reset (regression since the config.enc -> PerPluginStore
    migration)."""
    server_dir = mock_fs["home"] / ".wet-mcp"
    server_dir.mkdir()
    (server_dir / "config.json").write_text("{}")
    (server_dir / ".secret").write_bytes(b"machine-key-bytes")

    paths = _enumerate(["wet-mcp"], keep_data=True)
    path_names = [p.name for p in paths]
    assert "config.json" in path_names
    assert ".secret" in path_names


def test_enumerate_wipes_per_plugin_store_subs_tree(mock_fs):
    """Multi-user mode writes ~/.<server>/subs/<sub>/config.json and
    subs/<sub>/tokens/<provider>.json (per storage/backends.py _key_to_path).
    The whole subs/ tree must be enumerated for wiping."""
    server_dir = mock_fs["home"] / ".wet-mcp"
    sub_dir = server_dir / "subs" / "user-a"
    sub_dir.mkdir(parents=True)
    (sub_dir / "config.json").write_text("{}")
    tokens_dir = sub_dir / "tokens"
    tokens_dir.mkdir()
    (tokens_dir / "google_drive.json").write_text("{}")

    paths = _enumerate(["wet-mcp"], keep_data=True)
    path_names = [p.name for p in paths]
    assert "subs" in path_names


def test_enumerate_per_plugin_store_missing_files_no_error(mock_fs):
    """Server dir exists but has none of config.json/.secret/subs -- must not
    error, and must not enumerate anything for it."""
    server_dir = mock_fs["home"] / ".wet-mcp"
    server_dir.mkdir()

    paths = _enumerate(["wet-mcp"], keep_data=True)
    assert paths == []


def test_enumerate_per_plugin_store_other_plugin_untouched(mock_fs):
    """Cleaning one server must not enumerate another server's PerPluginStore
    files, even if both live directly under home."""
    server_dir = mock_fs["home"] / ".wet-mcp"
    server_dir.mkdir()
    (server_dir / "config.json").write_text("{}")

    other_dir = mock_fs["home"] / ".mnemo-mcp"
    other_dir.mkdir()
    (other_dir / "config.json").write_text("{}")

    paths = _enumerate(["wet-mcp"], keep_data=True)
    assert all("mnemo-mcp" not in str(p) for p in paths)
    assert any(p == server_dir / "config.json" for p in paths)


def test_main_wipes_per_plugin_store_files_e2e(mock_fs, monkeypatch):
    """End-to-end regression check: running mcp-clean-state must actually
    delete config.json and .secret from disk -- the exact bug this fixes."""
    server_dir = mock_fs["home"] / ".wet-mcp"
    server_dir.mkdir()
    cfg = server_dir / "config.json"
    cfg.write_text("{}")
    secret = server_dir / ".secret"
    secret.write_bytes(b"key")

    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp"])

    exit_code = main(["--server", "wet-mcp", "--yes"])

    assert exit_code == 0
    assert not cfg.exists()
    assert not secret.exists()


def test_main_per_plugin_store_other_server_survives(mock_fs, monkeypatch):
    """Cleaning wet-mcp must not remove mnemo-mcp's PerPluginStore files."""
    wet_dir = mock_fs["home"] / ".wet-mcp"
    wet_dir.mkdir()
    (wet_dir / "config.json").write_text("{}")

    mnemo_dir = mock_fs["home"] / ".mnemo-mcp"
    mnemo_dir.mkdir()
    mnemo_cfg = mnemo_dir / "config.json"
    mnemo_cfg.write_text("{}")

    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp", "mnemo-mcp"])

    exit_code = main(["--server", "wet-mcp", "--yes"])

    assert exit_code == 0
    assert not (wet_dir / "config.json").exists()
    assert mnemo_cfg.exists()


def test_main_dry_run_per_plugin_store_not_deleted(mock_fs, monkeypatch, capsys):
    """--dry-run must list PerPluginStore config.json/.secret without deleting
    them (mirrors test_main_dry_run for the legacy config.enc path)."""
    server_dir = mock_fs["home"] / ".wet-mcp"
    server_dir.mkdir()
    cfg = server_dir / "config.json"
    cfg.write_text("{}")
    secret = server_dir / ".secret"
    secret.write_bytes(b"key")

    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp"])

    exit_code = main(["--dry-run", "--server", "wet-mcp"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "[dry-run] Would remove" in captured.out
    assert str(cfg) in captured.out
    assert str(secret) in captured.out
    assert cfg.exists()
    assert secret.exists()


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


def test_confirm_assume_yes_bypasses_tty_check(monkeypatch):
    """--yes short-circuits the prompt regardless of tty state."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert _confirm(True) is True


def test_confirm_non_tty_without_assume_yes_refuses(monkeypatch, capsys):
    """Non-interactive callers must pass --yes explicitly -- the old
    sys.stdin.isatty() auto-yes fallback let any non-interactive wrapper
    silently confirm destructive credential deletion."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert _confirm(False) is False
    assert "--yes" in capsys.readouterr().err


def test_confirm_tty_prompt_unchanged(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdin.readline", lambda: "y\n")
    assert _confirm(False) is True


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

    exit_code = main(["--server", "wet-mcp", "--verbose", "--yes"])

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

    def mock_rmtree(p):
        raise OSError("rmtree error")

    monkeypatch.setattr(shutil, "rmtree", mock_rmtree)

    exit_code = main(["--no-keep-data", "--server", "wet-mcp", "--yes"])
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


def test_main_dry_run_skips_confirm_even_non_tty_without_yes(mock_fs, monkeypatch, capsys):
    """--dry-run never mutates the filesystem, so it must succeed even when
    non-interactive and --yes was not passed (confirmation is never reached)."""
    (mock_fs["config"] / "config.enc").write_text("dummy")
    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    exit_code = main(["--dry-run", "--server", "wet-mcp"])

    assert exit_code == 0
    assert (mock_fs["config"] / "config.enc").exists()


def test_main_abort(mock_fs, monkeypatch, capsys):
    (mock_fs["config"] / "config.enc").write_text("dummy")
    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp"])

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdin.readline", lambda: "n\n")

    exit_code = main(["--server", "wet-mcp"])

    assert exit_code == 1
    assert (mock_fs["config"] / "config.enc").exists()


def test_main_non_tty_without_yes_refuses(mock_fs, monkeypatch, capsys):
    """Regression pin for the auto-yes footgun: a non-interactive caller that
    forgets --yes must abort with exit code 1 and delete nothing."""
    cfg_file = mock_fs["config"] / "config.enc"
    cfg_file.write_text("dummy")
    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    exit_code = main(["--server", "wet-mcp"])

    assert exit_code == 1
    assert cfg_file.exists()
    captured = capsys.readouterr()
    assert "--yes" in captured.err
    assert "Aborted." in captured.out


def test_main_non_tty_with_yes_proceeds(mock_fs, monkeypatch):
    cfg_file = mock_fs["config"] / "config.enc"
    cfg_file.write_text("dummy")
    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    exit_code = main(["--server", "wet-mcp", "--yes"])

    assert exit_code == 0
    assert not cfg_file.exists()


def test_main_tty_input_y_proceeds(mock_fs, monkeypatch):
    """tty prompt path is unchanged: interactive 'y' still proceeds without
    --yes."""
    cfg_file = mock_fs["config"] / "config.enc"
    cfg_file.write_text("dummy")
    monkeypatch.setattr("mcp_core.scripts.clean_state.ALL_SERVERS", ["wet-mcp"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdin.readline", lambda: "y\n")

    exit_code = main(["--server", "wet-mcp"])

    assert exit_code == 0
    assert not cfg_file.exists()


def test_main_kill_daemons_flag(monkeypatch):
    mock_kill = MagicMock(return_value=(1, 2))
    monkeypatch.setattr("mcp_core.scripts.clean_state.kill_daemons", mock_kill)

    exit_code = main(["--kill-daemons", "--yes"])

    assert exit_code == 0
    mock_kill.assert_called_once()


def test_main_kill_daemons_non_tty_without_yes_refuses(monkeypatch):
    """--kill-daemons SIGKILLs live processes -- same footgun class as
    credential deletion, so it must be gated behind the same confirmation."""
    mock_kill = MagicMock(return_value=(1, 2))
    monkeypatch.setattr("mcp_core.scripts.clean_state.kill_daemons", mock_kill)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    exit_code = main(["--kill-daemons"])

    assert exit_code == 1
    mock_kill.assert_not_called()


def test_main_kill_daemons_tty_input_y_proceeds(monkeypatch):
    mock_kill = MagicMock(return_value=(1, 2))
    monkeypatch.setattr("mcp_core.scripts.clean_state.kill_daemons", mock_kill)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdin.readline", lambda: "y\n")

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
