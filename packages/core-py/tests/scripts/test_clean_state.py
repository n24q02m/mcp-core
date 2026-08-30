import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mcp_core.scripts.clean_state import (
    ALL_SERVERS,
    _enumerate,
    _ts_config_base,
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


def test_ts_config_base_uses_macos_env_paths_root(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setattr("mcp_core.scripts.clean_state._home", lambda: home)
    monkeypatch.setattr("mcp_core.scripts.clean_state.sys.platform", "darwin")

    assert _ts_config_base() == home / "Library" / "Preferences" / "mcp"


@pytest.mark.parametrize(
    ("alias", "server", "store_dir"),
    [
        ("notion", "better-notion-mcp", ".better-notion-mcp"),
        ("email", "better-email-mcp", ".better-email-mcp"),
        ("telegram", "better-telegram-mcp", ".telegram-mcp"),
        ("godot", "better-godot-mcp", None),
        ("workspace", "better-workspace-mcp", ".better-workspace-mcp"),
        ("wet", "wet-mcp", ".wet-mcp"),
        ("mnemo", "mnemo-mcp", ".mnemo-mcp"),
        ("crg", "better-code-review-graph", ".better-code-review-graph-mcp"),
        ("imagine", "imagine-mcp", ".imagine-mcp"),
    ],
)
def test_main_accepts_documented_alias_and_full_name(mock_fs, alias, server, store_dir):
    if store_dir is None:
        decoy_dir = mock_fs["home"] / ".better-godot-mcp"
        decoy_dir.mkdir()
        decoy = decoy_dir / "config.json"
        decoy.write_text("{}")
        for server_arg in (alias, server):
            assert main(["--server", server_arg, "--yes"]) == 0
            assert decoy.exists()
        return

    server_dir = mock_fs["home"] / store_dir
    server_dir.mkdir()
    config = server_dir / "config.json"
    for server_arg in (alias, server):
        config.write_text("{}")
        assert main(["--server", server_arg, "--yes"]) == 0
        assert not config.exists()


def test_main_removes_email_legacy_tokens_file(mock_fs):
    token_file = mock_fs["home"] / ".better-email-mcp" / "tokens.json"
    token_file.parent.mkdir()
    token_file.write_text("{}")

    assert main(["--server", "email", "--yes"]) == 0
    assert not token_file.exists()


def test_main_removes_telegram_credentials_from_store_and_both_data_roots(mock_fs, monkeypatch):
    default_data_dir = mock_fs["home"] / ".better-telegram-mcp"
    configured_data_dir = mock_fs["home"] / "telegram-data"
    store_dir = mock_fs["home"] / ".telegram-mcp"
    credential_paths = [
        store_dir / "tokens" / "app-identity.json",
        store_dir / "tokens" / "app-identity.json.tmp",
        default_data_dir / ".secret",
        default_data_dir / "stale.session",
        configured_data_dir / ".secret",
        configured_data_dir / "user_sessions" / "current.session",
        configured_data_dir / "user_sessions" / "current.session-journal",
        configured_data_dir / "user_sessions" / "current.session-wal",
        configured_data_dir / "user_sessions" / "current.session-shm",
    ]
    app_data_paths = [
        default_data_dir / "messages.db",
        configured_data_dir / "messages.db",
        configured_data_dir / "downloads" / "keep.bin",
    ]
    for path in credential_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-credential")
    for path in app_data_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-app-data")
    monkeypatch.setenv("TELEGRAM_DATA_DIR", str(configured_data_dir))

    assert main(["--server", "telegram", "--yes"]) == 0
    assert all(not path.exists() for path in credential_paths)
    assert all(path.read_text() == "synthetic-app-data" for path in app_data_paths)


def test_main_removes_mnemo_credentials_from_every_source_root(mock_fs, monkeypatch):
    default_data_dir = mock_fs["home"] / ".mnemo-mcp"
    configured_data_dir = mock_fs["home"] / "mnemo-data"
    db_data_dir = mock_fs["home"] / "mnemo-db-root"
    legacy_db_data_dir = mock_fs["home"] / "mnemo-legacy-db-root"
    data_roots = [
        default_data_dir,
        configured_data_dir,
        db_data_dir,
        legacy_db_data_dir,
    ]
    credential_paths = []
    app_data_paths = []
    for index, data_root in enumerate(data_roots):
        credential_paths.extend(
            [
                data_root / "tokens" / "provider.json",
                data_root / "subs" / f"user-{index}" / "config.json",
                data_root / "subs" / f"user-{index}" / "tokens" / "provider.json",
            ]
        )
        app_data_paths.extend(
            [
                data_root / "memories.db",
                data_root / "subs" / f"user-{index}" / "passport.db",
            ]
        )
    for path in credential_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-credential")
    for path in app_data_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-app-data")
    monkeypatch.setenv("MNEMO_DATA_DIR", str(configured_data_dir))
    monkeypatch.setenv("DB_PATH", str(db_data_dir / "mnemo.db"))
    monkeypatch.setenv("MNEMO_DB_PATH", str(legacy_db_data_dir / "mnemo.db"))

    assert main(["--server", "mnemo", "--yes"]) == 0
    assert all(not path.exists() for path in credential_paths)
    assert all(path.read_text() == "synthetic-app-data" for path in app_data_paths)


def test_main_removes_crg_credentials_from_default_and_override_roots(mock_fs, monkeypatch):
    default_data_dir = mock_fs["home"] / ".crg"
    configured_data_dir = mock_fs["home"] / "crg-data"
    credential_paths = []
    graph_paths = []
    for index, data_root in enumerate((default_data_dir, configured_data_dir)):
        sub_dir = data_root / "subs" / f"user-{index}"
        credential_paths.extend([sub_dir / "config.json", sub_dir / "tokens" / "provider.json"])
        graph_paths.append(sub_dir / "graph.db")
    for path in credential_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-credential")
    for path in graph_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-graph-data")
    monkeypatch.setenv("CRG_DATA_DIR", str(configured_data_dir))

    assert main(["--server", "crg", "--yes"]) == 0
    assert all(not path.exists() for path in credential_paths)
    assert all(path.read_text() == "synthetic-graph-data" for path in graph_paths)


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
    assert not sub_config.exists()
    assert not token.exists()
    assert sentinel.read_text() == "synthetic-app-data"


def test_help_reports_all_nine_servers(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "Default: all 9." in captured.out
    assert "full server name or alias" in captured.out


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


def test_main_removes_relay_state_and_atomic_config_temps_but_keeps_identity(mock_fs, monkeypatch):
    ts_config = mock_fs["home"] / "ts-config"
    ts_config.mkdir()
    monkeypatch.setattr("mcp_core.scripts.clean_state._ts_config_base", lambda: ts_config)
    credential_paths = [
        mock_fs["config"] / "config.enc.tmp",
        mock_fs["config"] / "relay-session-wet",
        mock_fs["config"] / "relay-session-wet.tmp",
        ts_config / "config.enc.tmp",
        ts_config / "relay-session-email.lock",
        ts_config / "relay-session-email.lock.tmp",
        mock_fs["legacy"] / "relay-session-crg.lock",
    ]
    identity_paths = [
        mock_fs["home"] / ".mcp-relay" / "jwt-keys" / "signing.pem",
        mock_fs["home"] / ".mcp-core" / "jwt-keys" / "signing.pem",
    ]
    for path in credential_paths:
        path.write_text("synthetic-setup-state")
    for path in identity_paths:
        path.parent.mkdir(parents=True)
        path.write_text("synthetic-system-identity")

    assert main(["--server", "godot", "--yes"]) == 0
    assert all(not path.exists() for path in credential_paths)
    assert all(path.read_text() == "synthetic-system-identity" for path in identity_paths)


def test_enumerate_with_data(mock_fs):
    server_dir = mock_fs["home"] / ".wet-mcp"
    server_dir.mkdir()
    data_dir = server_dir / "data"
    data_dir.mkdir()

    paths = _enumerate(["wet-mcp"], keep_data=False)
    path_names = [p.name for p in paths]
    assert "data" in path_names


def test_no_keep_data_never_enumerates_protected_directory_roots(mock_fs, tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    monkeypatch.chdir(checkout)
    protected_roots = {
        Path(checkout.anchor),
        mock_fs["home"],
        mock_fs["home"].parent,
        checkout,
        checkout.parent,
    }

    for protected_root in protected_roots:
        with monkeypatch.context() as scoped:
            scoped.setenv("DB_PATH", str(protected_root / "mnemo.db"))
            scoped.setenv("MNEMO_DATA_DIR", str(protected_root))
            scoped.delenv("MNEMO_DB_PATH", raising=False)
            paths = _enumerate(["mnemo-mcp"], keep_data=False)
        assert protected_root not in paths


def test_no_keep_data_relative_mnemo_db_removes_only_owned_files(mock_fs, tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    monkeypatch.chdir(checkout)
    monkeypatch.setenv("DB_PATH", "mnemo.db")
    monkeypatch.delenv("MNEMO_DB_PATH", raising=False)
    monkeypatch.delenv("MNEMO_DATA_DIR", raising=False)

    owned_paths = [
        checkout / "mnemo.db",
        checkout / "mnemo.db-wal",
        checkout / "mnemo.db-shm",
        checkout / "mnemo.db-journal",
    ]
    sibling_paths = [
        checkout / "sync_folder_ids.json",
        checkout / "passport-user.mnemo",
        checkout / "tokens" / "provider.json",
        checkout / "pyproject.toml",
        checkout / "src" / "app.py",
    ]
    for path in owned_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-owned-state")
    for path in sibling_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-checkout-data")

    assert main(["--server", "mnemo", "--no-keep-data", "--yes"]) == 0
    assert checkout.is_dir()
    assert all(not path.exists() for path in owned_paths)
    assert all(path.read_text() == "synthetic-checkout-data" for path in sibling_paths)


def test_protected_override_roots_are_not_scanned(mock_fs, tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    monkeypatch.chdir(checkout)
    protected_paths = [
        checkout / ".secret",
        checkout / "user_sessions" / "unrelated.session",
        checkout / "messages.db",
        checkout / "downloads" / "media.bin",
        checkout / "config.json",
        checkout / "config.json.tmp",
        checkout / "tokens" / "provider.json",
        checkout / "subs" / "user-a" / "config.json",
        checkout / "subs" / "user-a" / "tokens" / "provider.json",
        checkout / "sync_folder_ids.json",
        checkout / "passport-user.mnemo",
        checkout / "subs" / "user-a" / "graph.db",
    ]
    for path in protected_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-unrelated-state")
    monkeypatch.setenv("TELEGRAM_DATA_DIR", str(checkout))
    monkeypatch.setenv("MNEMO_DATA_DIR", str(checkout))
    monkeypatch.setenv("DB_PATH", str(checkout / "mnemo.db"))
    monkeypatch.delenv("MNEMO_DB_PATH", raising=False)
    monkeypatch.setenv("CRG_DATA_DIR", str(checkout))

    for server in ("better-telegram-mcp", "mnemo-mcp", "better-code-review-graph"):
        paths = _enumerate([server], keep_data=False)
        assert all(path not in paths for path in protected_paths)


def test_no_keep_data_removes_only_owned_telegram_and_crg_data(mock_fs):
    telegram_root = mock_fs["home"] / ".better-telegram-mcp"
    telegram_owned = [
        telegram_root / "messages.db",
        telegram_root / "messages.db-wal",
        telegram_root / "messages.db-shm",
        telegram_root / "messages.db-journal",
        telegram_root / "downloads" / "media.bin",
    ]
    telegram_sibling = telegram_root / "operator-notes.txt"
    for path in telegram_owned:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-app-data")
    telegram_sibling.write_text("retain")

    assert main(["--server", "telegram", "--no-keep-data", "--yes"]) == 0
    assert all(not path.exists() for path in telegram_owned)
    assert telegram_sibling.read_text() == "retain"

    crg_root = mock_fs["home"] / ".crg"
    graph_root = crg_root / "subs" / "user-a"
    crg_owned = [
        graph_root / "graph.db",
        graph_root / "graph.db-wal",
        graph_root / "graph.db-shm",
        graph_root / "graph.db-journal",
    ]
    crg_sibling = crg_root / "operator-notes.txt"
    for path in crg_owned:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-graph-data")
    crg_sibling.parent.mkdir(parents=True, exist_ok=True)
    crg_sibling.write_text("retain")

    assert main(["--server", "crg", "--no-keep-data", "--yes"]) == 0
    assert all(not path.exists() for path in crg_owned)
    assert crg_sibling.read_text() == "retain"


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


def test_enumerate_per_plugin_store_root_tokens_and_atomic_temps(mock_fs):
    server_dir = mock_fs["home"] / ".wet-mcp"
    sub_dir = server_dir / "subs" / "user-a"
    credential_paths = [
        server_dir / "config.json.tmp",
        server_dir / ".secret.tmp",
        server_dir / "tokens" / "app-identity.json",
        server_dir / "tokens" / "app-identity.json.tmp",
        sub_dir / "config.json.tmp",
        sub_dir / "tokens" / "provider.json.tmp",
    ]
    app_temp = sub_dir / "index-build.tmp"
    for path in credential_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-credential")
    app_temp.write_text("synthetic-app-data")

    paths = _enumerate(["wet-mcp"], keep_data=True)
    assert all(path in paths for path in credential_paths)
    assert app_temp not in paths


def test_enumerate_selects_per_plugin_store_credentials_not_app_data(mock_fs):
    """Per-sub credentials can share a directory with server application data."""
    server_dir = mock_fs["home"] / ".wet-mcp"
    sub_dir = server_dir / "subs" / "user-a"
    sub_dir.mkdir(parents=True)
    config = sub_dir / "config.json"
    config.write_text("{}")
    tokens_dir = sub_dir / "tokens"
    tokens_dir.mkdir()
    token = tokens_dir / "google_drive.json"
    token.write_text("{}")
    app_data = sub_dir / "state.db"
    app_data.write_text("synthetic-app-data")

    paths = _enumerate(["wet-mcp"], keep_data=True)
    assert config in paths
    assert token in paths
    assert app_data not in paths
    assert sub_dir not in paths


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


def test_ts_config_base_windows_env_paths_root(monkeypatch, tmp_path):
    monkeypatch.setattr("mcp_core.scripts.clean_state.sys.platform", "win32")
    monkeypatch.setenv("APPDATA", str(tmp_path))

    assert _ts_config_base() == tmp_path / "mcp" / "Config"


def test_home_and_python_config_base():
    from mcp_core.scripts.clean_state import _home, _python_config_base

    assert isinstance(_home(), Path)
    assert isinstance(_python_config_base(), Path)
