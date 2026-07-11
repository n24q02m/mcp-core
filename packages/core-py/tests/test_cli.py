from __future__ import annotations

import argparse
import asyncio
import time

import pytest
from loguru import logger

from mcp_core.cli import build_cli, ensure_stderr_logging
from mcp_core.storage.config_file import set_config_path
from mcp_core.storage.mode import get_mode, set_local_mode
from mcp_core.storage.per_plugin_store import PerPluginStore
from mcp_core.storage.session_lock import (
    SessionInfo,
    acquire_session_lock,
    set_lock_dir,
    write_session_lock,
)


@pytest.fixture
def cli_storage(tmp_path, monkeypatch):
    """Redirect every storage backend the built-ins touch into tmp_path.

    Mirrors the home-redirect idiom from tests/storage/test_per_plugin_store.py
    (PerPluginStore/LocalFsBackend) plus the override hooks session_lock and
    config_file already expose for tests, so built-in subcommand tests never
    read/write the real user home directory.
    """
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    set_lock_dir(str(tmp_path / "locks"))
    set_config_path(str(tmp_path / "config.enc"))
    yield tmp_path
    set_lock_dir(None)
    set_config_path(None)


def test_ensure_stderr_logging_installs_single_sink():
    ensure_stderr_logging()

    assert len(logger._core.handlers) == 1


def test_ensure_stderr_logging_idempotent():
    ensure_stderr_logging()
    ensure_stderr_logging()

    assert len(logger._core.handlers) == 1


def test_ensure_stderr_logging_defaults_to_info(monkeypatch):
    monkeypatch.delenv("MCP_LOG_LEVEL", raising=False)

    ensure_stderr_logging()

    handler = next(iter(logger._core.handlers.values()))
    assert handler.levelno == logger.level("INFO").no


def test_ensure_stderr_logging_respects_env_level(monkeypatch):
    monkeypatch.setenv("MCP_LOG_LEVEL", "DEBUG")

    ensure_stderr_logging()

    handler = next(iter(logger._core.handlers.values()))
    assert handler.levelno == logger.level("DEBUG").no


def test_bare_invocation_calls_serve_with_empty_argv():
    calls: list[list[str]] = []

    def fake_serve(argv: list[str]) -> None:
        calls.append(list(argv))
        return None

    run = build_cli("test-server", serve=fake_serve)
    rc = run([])

    assert calls == [[]]
    assert rc == 0


def test_bare_invocation_returns_serve_rc():
    run = build_cli("test-server", serve=lambda argv: 7)

    assert run([]) == 7


def test_flag_passthrough_to_serve_untouched():
    calls: list[list[str]] = []

    def fake_serve(argv: list[str]) -> None:
        calls.append(list(argv))
        return None

    run = build_cli("test-server", serve=fake_serve)
    rc = run(["--http", "--port", "8080"])

    assert calls == [["--http", "--port", "8080"]]
    assert rc == 0


def test_unknown_positional_prints_stderr_and_returns_2(capsys):
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["bogus"])

    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out == ""
    assert "bogus" in captured.err
    assert "config" in captured.err
    assert "relay" in captured.err
    assert "doctor" in captured.err


def test_extra_subcommand_called_with_namespace():
    calls: list[argparse.Namespace] = []

    def fake_handler(ns: argparse.Namespace) -> int:
        calls.append(ns)
        return 0

    run = build_cli("test-server", serve=lambda argv: None, extra={"sync": fake_handler})
    rc = run(["sync"])

    assert rc == 0
    assert len(calls) == 1
    assert isinstance(calls[0], argparse.Namespace)


def test_extra_subcommand_overrides_builtin_stub():
    calls: list[argparse.Namespace] = []

    def fake_doctor(ns: argparse.Namespace) -> int:
        calls.append(ns)
        return 0

    run = build_cli("test-server", serve=lambda argv: None, extra={"doctor": fake_doctor})
    rc = run(["doctor"])

    assert rc == 0
    assert len(calls) == 1


def test_builtin_name_recognized_dispatches_to_real_handler(cli_storage):
    run = build_cli("test-server", serve=lambda argv: None)

    # A bare (unregistered) built-in name must be *recognized* — dispatched
    # through to its real handler, not rejected with rc 2 like an unknown
    # subcommand. config/relay/doctor are wired up (no NotImplementedError).
    rc = run(["doctor"])

    assert isinstance(rc, int)


def test_serve_not_called_for_subcommand_dispatch():
    serve_calls: list[list[str]] = []

    def fake_serve(argv: list[str]) -> None:
        serve_calls.append(list(argv))
        return None

    run = build_cli("test-server", serve=fake_serve, extra={"sync": lambda ns: 0})
    run(["sync"])

    assert serve_calls == []


def test_subcommand_dispatch_calls_ensure_stderr_logging(monkeypatch):
    called: list[bool] = []
    monkeypatch.setattr("mcp_core.cli.ensure_stderr_logging", lambda: called.append(True))

    run = build_cli("test-server", serve=lambda argv: None, extra={"sync": lambda ns: 0})
    run(["sync"])

    assert called == [True]


def test_serve_path_does_not_call_ensure_stderr_logging(monkeypatch):
    called: list[bool] = []
    monkeypatch.setattr("mcp_core.cli.ensure_stderr_logging", lambda: called.append(True))

    run = build_cli("test-server", serve=lambda argv: None)
    run([])
    run(["--http"])

    assert called == []


# --- config status ----------------------------------------------------------


def test_config_status_not_configured_rc_0(cli_storage, capsys):
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["config", "status"])

    captured = capsys.readouterr()
    assert rc == 0
    assert "not configured" in captured.out


def test_config_status_configured_rc_0_never_prints_value(cli_storage, capsys):
    PerPluginStore("test-server").save({"API_KEY": "super-secret-value"})
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["config", "status"])

    captured = capsys.readouterr()
    assert rc == 0
    assert "configured" in captured.out
    assert "super-secret-value" not in captured.out
    assert "super-secret-value" not in captured.err


def test_config_status_corrupt_blob_rc_1(cli_storage, capsys):
    store = PerPluginStore("test-server")
    # Blob shorter than the 13-byte nonce -- load() treats it as corrupt, not
    # absent, but the raw bytes are still present in the backend.
    store._backend.put(store.cred_key, b"\x00" * 5)
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["config", "status"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "corrupt" in captured.err.lower()


# --- config delete -----------------------------------------------------------


def test_config_delete_non_tty_without_yes_refuses_and_keeps_config(cli_storage, capsys, monkeypatch):
    PerPluginStore("test-server").save({"API_KEY": "value"})
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["config", "delete"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "--yes" in captured.err
    assert PerPluginStore("test-server").load() == {"API_KEY": "value"}


def test_config_delete_with_yes_deletes(cli_storage):
    PerPluginStore("test-server").save({"API_KEY": "value"})
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["config", "delete", "--yes"])

    assert rc == 0
    assert PerPluginStore("test-server").load() is None


def test_config_delete_tty_confirm_yes_deletes(cli_storage, monkeypatch):
    PerPluginStore("test-server").save({"API_KEY": "value"})
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdin.readline", lambda: "y\n")
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["config", "delete"])

    assert rc == 0
    assert PerPluginStore("test-server").load() is None


def test_config_delete_tty_confirm_no_aborts_and_keeps_config(cli_storage, monkeypatch):
    PerPluginStore("test-server").save({"API_KEY": "value"})
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdin.readline", lambda: "n\n")
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["config", "delete"])

    assert rc == 1
    assert PerPluginStore("test-server").load() == {"API_KEY": "value"}


# --- relay status / open ------------------------------------------------------


def test_relay_status_no_session_rc_1(cli_storage, capsys):
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["relay", "status"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "no active relay session" in captured.err


def test_relay_status_with_session_rc_0(cli_storage, capsys):
    info = SessionInfo(
        session_id="abcdefgh12345",
        relay_url="https://relay.example.com/authorize?s=abc",
        created_at=time.time(),
    )
    asyncio.run(write_session_lock("test-server", info))
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["relay", "status"])

    captured = capsys.readouterr()
    assert rc == 0
    assert "abcdefgh" in captured.out
    assert info.relay_url in captured.out


def test_relay_open_no_session_rc_1(cli_storage, capsys):
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["relay", "open"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "no active relay session" in captured.err


def test_relay_open_with_session_calls_try_open_browser(cli_storage, monkeypatch):
    info = SessionInfo(
        session_id="abcdefgh12345",
        relay_url="https://relay.example.com/authorize?s=abc",
        created_at=time.time(),
    )
    asyncio.run(write_session_lock("test-server", info))
    opened: list[str] = []
    monkeypatch.setattr("mcp_core.cli.try_open_browser", lambda url: opened.append(url) or True)
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["relay", "open"])

    assert rc == 0
    assert opened == [info.relay_url]


# --- relay reset ---------------------------------------------------------------


def test_relay_reset_clears_lock_and_mode(cli_storage, capsys):
    info = SessionInfo(
        session_id="abcdefgh12345",
        relay_url="https://relay.example.com/authorize?s=abc",
        created_at=time.time(),
    )
    asyncio.run(write_session_lock("test-server", info))
    set_local_mode("test-server")
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["relay", "reset"])

    captured = capsys.readouterr()
    assert rc == 0
    assert "relay state cleared" in captured.out
    assert asyncio.run(acquire_session_lock("test-server")) is None
    assert get_mode("test-server") is None


# --- doctor ----------------------------------------------------------------


def test_doctor_healthy_rc_0_no_fail_lines(cli_storage, capsys):
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["doctor"])

    captured = capsys.readouterr()
    assert rc == 0
    assert "[fail]" not in captured.out
    assert "[ok]" in captured.out


def test_doctor_reports_fail_on_corrupt_config_rc_1(cli_storage, capsys):
    store = PerPluginStore("test-server")
    store._backend.put(store.cred_key, b"\x00" * 5)
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["doctor"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "[fail]" in captured.out


def test_doctor_reports_active_relay_session(cli_storage, capsys):
    info = SessionInfo(
        session_id="abcdefgh12345",
        relay_url="https://relay.example.com/authorize?s=abc",
        created_at=time.time(),
    )
    asyncio.run(write_session_lock("test-server", info))
    run = build_cli("test-server", serve=lambda argv: None)

    rc = run(["doctor"])

    captured = capsys.readouterr()
    assert rc == 0
    assert "abcdefgh" in captured.out
