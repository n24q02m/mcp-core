import subprocess
import sys


def test_help_runs_includes_kill_daemons_flag():
    result = subprocess.run(
        [sys.executable, "-m", "mcp_core.scripts.clean_state", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--kill-daemons" in result.stdout


def test_help_runs():
    result = subprocess.run(
        [sys.executable, "-m", "mcp_core.scripts.clean_state", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Clear MCP server credentials" in result.stdout
    assert "--keep-data" in result.stdout
    assert "--server" in result.stdout
    assert "--dry-run" in result.stdout


def test_dry_run_lists_paths(tmp_path, monkeypatch):
    # Set up fake state
    config_dir = tmp_path / ".config" / "mcp"
    config_dir.mkdir(parents=True)
    (config_dir / "config.enc").write_text("encrypted")
    (config_dir / "locks").mkdir()
    (config_dir / "locks" / "wet-mcp-1234.lock").write_text("lock")
    (config_dir / "cache").mkdir()
    (config_dir / "cache" / "wet-mcp-1234-2.28-1.11.tools.json").write_text("{}")

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows

    result = subprocess.run(
        [sys.executable, "-m", "mcp_core.scripts.clean_state", "--dry-run"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "config.enc" in result.stdout
    assert "wet-mcp-1234.lock" in result.stdout
    assert "tools.json" in result.stdout
    # Files NOT removed
    assert (config_dir / "config.enc").exists()


def test_actual_clean(tmp_path, monkeypatch):
    config_dir = tmp_path / ".config" / "mcp"
    config_dir.mkdir(parents=True)
    (config_dir / "config.enc").write_text("encrypted")

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    result = subprocess.run(
        [sys.executable, "-m", "mcp_core.scripts.clean_state"],
        capture_output=True,
        text=True,
        input="y\n",
    )

    assert result.returncode == 0
    assert not (config_dir / "config.enc").exists()


def test_keep_data_default(tmp_path, monkeypatch):
    """Default --keep-data ON: app data dirs preserved."""
    home = tmp_path
    (home / ".wet-mcp" / "data").mkdir(parents=True)
    (home / ".wet-mcp" / "data" / "search.sqlite").write_text("data")
    (home / ".wet-mcp" / "tokens").mkdir(parents=True)
    (home / ".wet-mcp" / "tokens" / "google_drive.json").write_text("{}")

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    result = subprocess.run(
        [sys.executable, "-m", "mcp_core.scripts.clean_state"],
        capture_output=True,
        text=True,
        input="y\n",
    )

    assert result.returncode == 0
    # Tokens cleared, data preserved
    assert not (home / ".wet-mcp" / "tokens" / "google_drive.json").exists()
    assert (home / ".wet-mcp" / "data" / "search.sqlite").exists()


def test_no_keep_data_wipes_app_data(tmp_path, monkeypatch):
    home = tmp_path
    (home / ".wet-mcp" / "data").mkdir(parents=True)
    (home / ".wet-mcp" / "data" / "search.sqlite").write_text("data")

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    result = subprocess.run(
        [sys.executable, "-m", "mcp_core.scripts.clean_state", "--no-keep-data"],
        capture_output=True,
        text=True,
        input="y\n",
    )

    assert result.returncode == 0
    assert not (home / ".wet-mcp" / "data" / "search.sqlite").exists()


def test_config_paths_includes_platformdirs_python_config(tmp_path, monkeypatch):
    """Python core-py uses platformdirs (LOCALAPPDATA on Windows, ~/.config
    on Linux). The clean script must enumerate that path, not just the
    legacy ~/.config/mcp/ tree (which is only correct on POSIX).
    """
    from mcp_core.scripts import clean_state

    fake = tmp_path / "platformdirs-mcp"
    fake.mkdir()
    (fake / "config.enc").write_text("encrypted")

    monkeypatch.setattr(clean_state, "_python_config_base", lambda: fake)
    monkeypatch.setattr(clean_state, "_legacy_posix_base", lambda: tmp_path / "_no_legacy")
    monkeypatch.setattr(clean_state, "_ts_config_base", lambda: None)

    paths = clean_state._config_paths()
    assert any(str(p).endswith("config.enc") for p in paths), paths
    assert (fake / "config.enc") in paths


def test_config_paths_includes_appdata_ts_config(tmp_path, monkeypatch):
    """TS core-ts (notion + email) writes to %APPDATA%\\mcp\\Config\\config.enc
    on Windows. The clean script must enumerate that distinct path even
    when Python's config.enc is also present.
    """
    from mcp_core.scripts import clean_state

    py_base = tmp_path / "py-base"
    py_base.mkdir()
    (py_base / "config.enc").write_text("py-encrypted")

    ts_base = tmp_path / "ts-base"
    ts_base.mkdir()
    (ts_base / "config.enc").write_text("ts-encrypted")

    monkeypatch.setattr(clean_state, "_python_config_base", lambda: py_base)
    monkeypatch.setattr(clean_state, "_ts_config_base", lambda: ts_base)
    monkeypatch.setattr(clean_state, "_legacy_posix_base", lambda: tmp_path / "_no_legacy")

    paths = clean_state._config_paths()
    assert (py_base / "config.enc") in paths
    assert (ts_base / "config.enc") in paths


def test_config_paths_dedupes_when_legacy_equals_platformdirs(tmp_path, monkeypatch):
    """On Linux, platformdirs returns ~/.config/mcp which equals the legacy
    base — must not enumerate config.enc twice.
    """
    from mcp_core.scripts import clean_state

    base = tmp_path / "shared"
    base.mkdir()
    (base / "config.enc").write_text("encrypted")

    monkeypatch.setattr(clean_state, "_python_config_base", lambda: base)
    monkeypatch.setattr(clean_state, "_legacy_posix_base", lambda: base)
    monkeypatch.setattr(clean_state, "_ts_config_base", lambda: None)

    paths = clean_state._config_paths()
    config_paths = [p for p in paths if p.name == "config.enc"]
    assert len(config_paths) == 1, paths


# ---------------------------------------------------------------------------
# kill_daemons (--kill-daemons flag) — added 2026-04-30 for migration to
# mcp-core 1.12.0 stdio-direct architecture.
# ---------------------------------------------------------------------------


def _write_lock(path, *, pid, port=8000, token="abc", spawned="2026-04-30T00:00:00+00:00"):
    """Write a 4-line legacy lock file matching ``lifecycle.lock`` layout."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{pid}\n{port}\n{token}\n{spawned}\n")


def test_kill_daemons_no_lock_dir(tmp_path, monkeypatch, capsys):
    """Missing lock dir returns (0, 0) and prints a no-op message."""
    from mcp_core.scripts import clean_state

    monkeypatch.setattr(clean_state, "_legacy_posix_base", lambda: tmp_path / "missing")
    killed, removed = clean_state.kill_daemons()
    captured = capsys.readouterr()
    assert (killed, removed) == (0, 0)
    assert "No lock directory" in captured.out


def test_kill_daemons_no_locks(tmp_path, monkeypatch, capsys):
    """Empty lock dir returns (0, 0) and prints a no-op message."""
    from mcp_core.scripts import clean_state

    base = tmp_path / "mcp-base"
    (base / "locks").mkdir(parents=True)
    monkeypatch.setattr(clean_state, "_legacy_posix_base", lambda: base)
    killed, removed = clean_state.kill_daemons()
    captured = capsys.readouterr()
    assert (killed, removed) == (0, 0)
    assert "No lock files" in captured.out


def test_kill_daemons_terminates_alive_and_removes_companions(tmp_path, monkeypatch, capsys):
    """Alive PID gets terminated; both lock files removed; companion cache +
    sentinel files removed; summary reports counts.
    """
    from mcp_core.scripts import clean_state

    base = tmp_path / "mcp-base"
    locks_dir = base / "locks"
    cache_dir = base / "cache"
    locks_dir.mkdir(parents=True)
    cache_dir.mkdir(parents=True)

    # Two locks: one "alive" (pid=1111), one "stale" (pid=2222 dead).
    alive_lock = locks_dir / "wet-mcp-1111.lock"
    stale_lock = locks_dir / "mnemo-mcp-2222.lock"
    _write_lock(alive_lock, pid=1111)
    _write_lock(stale_lock, pid=2222)

    # Companion tools.json cache files (one per lock).
    alive_cache = cache_dir / "wet-mcp-1111-2.28-1.11.tools.json"
    stale_cache = cache_dir / "mnemo-mcp-2222-2.28-1.11.tools.json"
    alive_cache.write_text("{}")
    stale_cache.write_text("{}")

    # Sentinel sibling.
    sentinel = locks_dir / "wet-mcp-1111.lock.tools-list-changed"
    sentinel.write_text("1")

    monkeypatch.setattr(clean_state, "_legacy_posix_base", lambda: base)

    # Stub liveness + termination so we don't actually kill any process.
    alive_pids = {1111}
    terminated = []

    def fake_is_pid_alive(pid):
        return pid in alive_pids

    def fake_terminate_daemon(pid):
        terminated.append(pid)
        alive_pids.discard(pid)

    monkeypatch.setattr("mcp_core.lifecycle.lock._is_pid_alive", fake_is_pid_alive)
    monkeypatch.setattr("mcp_core.lifecycle.lock._terminate_daemon", fake_terminate_daemon)

    killed, removed = clean_state.kill_daemons(verbose=True)
    captured = capsys.readouterr()

    assert killed == 1, f"expected 1 alive killed, got {killed}"
    assert removed == 2, f"expected 2 lock files removed, got {removed}"
    assert terminated == [1111]

    # Both locks removed.
    assert not alive_lock.exists()
    assert not stale_lock.exists()

    # Both companions removed.
    assert not alive_cache.exists()
    assert not stale_cache.exists()

    # Sentinel removed.
    assert not sentinel.exists()

    # Summary printed.
    assert "Killed 1 daemons" in captured.out
    assert "cleaned 2 lock files" in captured.out


def test_kill_daemons_handles_malformed_lock(tmp_path, monkeypatch, capsys):
    """A lock with non-integer PID line is skipped for kill but still removed."""
    from mcp_core.scripts import clean_state

    base = tmp_path / "mcp-base"
    locks_dir = base / "locks"
    locks_dir.mkdir(parents=True)

    bad = locks_dir / "wet-mcp-bad.lock"
    bad.write_text("not-a-pid\n8000\ntoken\n2026-04-30T00:00:00+00:00\n")

    monkeypatch.setattr(clean_state, "_legacy_posix_base", lambda: base)

    terminated = []

    def fake_terminate_daemon(pid):
        terminated.append(pid)

    monkeypatch.setattr("mcp_core.lifecycle.lock._is_pid_alive", lambda pid: False)
    monkeypatch.setattr("mcp_core.lifecycle.lock._terminate_daemon", fake_terminate_daemon)

    killed, removed = clean_state.kill_daemons()
    assert killed == 0
    assert removed == 1
    assert terminated == []
    assert not bad.exists()


def test_cli_kill_daemons_flag_invokes_function(tmp_path, monkeypatch):
    """`mcp-clean-state --kill-daemons` invokes kill_daemons and exits early."""
    from mcp_core.scripts import clean_state

    base = tmp_path / "mcp-base"
    (base / "locks").mkdir(parents=True)
    monkeypatch.setattr(clean_state, "_legacy_posix_base", lambda: base)

    calls = []

    def fake_kill(verbose=False):
        calls.append(verbose)
        return (0, 0)

    monkeypatch.setattr(clean_state, "kill_daemons", fake_kill)

    rc = clean_state.main(["--kill-daemons"])
    assert rc == 0
    assert calls == [False]

    rc = clean_state.main(["--kill-daemons", "--verbose"])
    assert rc == 0
    assert calls == [False, True]
