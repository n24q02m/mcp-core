"""Tests for ``run_stdio_config`` — the stdio-pure runner added 2026-05-02.

Per spec ``2026-05-01-stdio-pure-http-multiuser.md`` §5.5.5 the driver gains a
new entry point that drives the per-plugin stdio entry directly: ``uvx
<plugin>`` with env from skret, ``mcp.stdio_client`` handshake, ``tools/list``
+ representative ``tools/call``.

These tests stay at the helper level (no real ``uvx`` spawn, no skret) — they
validate the result-shape contract + the missing-env negative path. Live
integration coverage runs through ``make e2e-full``.
"""

from __future__ import annotations

import asyncio

import pytest

from e2e import driver
from e2e.driver import run_stdio_config


@pytest.mark.asyncio
async def test_stdio_runner_returns_pass_shape_when_handshake_ok(monkeypatch):
    """Successful uvx + handshake + tools/call -> ``status == "PASS"``,
    ``tool_calls >= 1``, and ``evidence`` echoes the tool name asserted."""

    monkeypatch.setattr(
        driver,
        "_resolve_stdio_env",
        lambda config: {"NOTION_TOKEN": "ntn_test_value_for_unit_test"},
    )

    async def fake_spawn(config, env):
        return {
            "status": "PASS",
            "tool_calls": 1,
            "evidence": ["pages.list"],
            "exit_code": 0,
            "stderr": "",
        }

    monkeypatch.setattr(driver, "_spawn_stdio_and_call_tool", fake_spawn)

    result = await run_stdio_config("notion-stdio")
    assert result["status"] == "PASS"
    assert result["tool_calls"] >= 1
    assert "evidence" in result


@pytest.mark.asyncio
async def test_stdio_runner_missing_env_exits_1(monkeypatch):
    """Pure pass-through env={} (skret bypassed) lets the plugin's own
    missing-cred handler fire. The runner reports the child's exit_code +
    stderr verbatim so the driver can match against the documented stderr
    format ('NOTION_TOKEN required for stdio mode but not set')."""

    async def fake_spawn(config, env):
        # Empty env triggers plugin's exit-1 missing-cred handler
        return {
            "status": "FAIL",
            "tool_calls": 0,
            "evidence": [],
            "exit_code": 1,
            "stderr": "[better-notion-mcp] NOTION_TOKEN required for stdio mode "
            "but not set.\n",
        }

    monkeypatch.setattr(driver, "_spawn_stdio_and_call_tool", fake_spawn)

    result = await run_stdio_config("notion-stdio", env={})
    assert result["status"] == "FAIL"
    assert result.get("exit_code") == 1
    assert "NOTION_TOKEN" in result.get("stderr", "")


@pytest.mark.asyncio
async def test_stdio_runner_unknown_config_id_raises(monkeypatch):
    with pytest.raises(KeyError, match="not-a-real-config"):
        await run_stdio_config("not-a-real-config")


def test_run_stdio_config_is_async():
    """``run_stdio_config`` must be a coroutine — the driver's
    aggregate dispatch wraps it in ``asyncio.run`` like the other
    stdio-direct path."""
    coro = (
        run_stdio_config.__wrapped__
        if hasattr(run_stdio_config, "__wrapped__")
        else run_stdio_config
    )
    assert asyncio.iscoroutinefunction(coro)


@pytest.mark.asyncio
async def test_multi_session_stdio_invariant_returns_pid_count(monkeypatch):
    """Multi-session stdio invariant: 3 concurrent processes must yield
    >=3 distinct PIDs (no shared state). The runner returns observed
    PID set + assertion verdict."""

    async def fake_spawn_n(plugin: str, n: int):
        # Simulate 3 distinct PIDs
        return [10001, 10002, 10003]

    monkeypatch.setattr(driver, "_spawn_n_stdio_processes", fake_spawn_n)

    result = await driver.run_multi_session_invariant_config(
        "multi-session-stdio", plugin="better-notion-mcp", mode="stdio"
    )
    assert result["status"] == "PASS"
    assert len(set(result["pids"])) >= 3


@pytest.mark.asyncio
async def test_multi_session_http_invariant_asserts_single_daemon(monkeypatch):
    """Multi-session HTTP invariant: 3 concurrent CC sessions must
    yield exactly 1 daemon PID (shared multi-user)."""

    async def fake_count_http(plugin: str):
        return [20001]

    monkeypatch.setattr(driver, "_count_http_daemon_pids", fake_count_http)

    result = await driver.run_multi_session_invariant_config(
        "multi-session-http", plugin="better-notion-mcp", mode="http"
    )
    assert result["status"] == "PASS"
    assert len(result["pids"]) == 1


@pytest.mark.asyncio
async def test_multi_session_stdio_invariant_fails_on_pid_sharing(monkeypatch):
    async def fake_spawn_n(plugin: str, n: int):
        # Simulate PID sharing (only 1 distinct) — invariant violation
        return [10001, 10001, 10001]

    monkeypatch.setattr(driver, "_spawn_n_stdio_processes", fake_spawn_n)

    result = await driver.run_multi_session_invariant_config(
        "multi-session-stdio", plugin="better-notion-mcp", mode="stdio"
    )
    assert result["status"] == "FAIL"
    assert "distinct" in result["reason"].lower()


@pytest.mark.asyncio
async def test_multi_session_http_invariant_fails_on_multi_daemon(monkeypatch):
    async def fake_count_http(plugin: str):
        # Multi-daemon proliferation invariant violation
        return [20001, 20002]

    monkeypatch.setattr(driver, "_count_http_daemon_pids", fake_count_http)

    result = await driver.run_multi_session_invariant_config(
        "multi-session-http", plugin="better-notion-mcp", mode="http"
    )
    assert result["status"] == "FAIL"
    assert "daemon" in result["reason"].lower()
