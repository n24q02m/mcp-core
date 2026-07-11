from __future__ import annotations

import argparse

import pytest
from loguru import logger

from mcp_core.cli import build_cli, ensure_stderr_logging


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


def test_builtin_name_recognized_dispatches_to_stub():
    run = build_cli("test-server", serve=lambda argv: None)

    # A bare (unregistered) built-in name must be *recognized* — dispatched
    # through to its stub handler, not rejected with rc 2 like an unknown
    # subcommand. The stub raises NotImplementedError until a later task
    # wires in the real config/relay/doctor handlers.
    with pytest.raises(NotImplementedError):
        run(["doctor"])


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
