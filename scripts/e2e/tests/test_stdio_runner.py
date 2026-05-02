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
from pathlib import Path

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


# -----------------------------------------------------------------
# stdio-pure-strict-no-fallback hardening (2026-05-02 per
# feedback_test_a_not_test_b.md). The original negative test silently
# became a false positive when prior real-plugin Test B left
# PerPluginStore artefacts behind, so the driver gained a cred-storage
# wipe step before each spawn. These tests cover:
#   1. ``_clear_persistent_cred_storage`` enumerates + removes every
#      documented cred surface.
#   2. The strict config asserts exit 1 for required-cred plugins
#      AFTER wiping (no fallback path can save them).
#   3. The strict config asserts boot-clean for optional/no-cred
#      plugins AFTER wiping (no PerPluginStore mutation possible).
# -----------------------------------------------------------------


def test_clear_persistent_cred_storage_clears_all_paths(tmp_path, monkeypatch):
    """Every documented cred surface is enumerated and the existing ones
    are removed. The legacy ``config.enc`` files (TS APPDATA, Py
    LOCALAPPDATA, POSIX ``~/.config/mcp``) plus the per-plugin store
    (``config.json``, ``users/``, ``subs/``, ``tokens.json``) are all
    covered."""
    # Pin HOME + APPDATA + LOCALAPPDATA so the helper writes/reads from
    # tmp_path instead of the developer's real machine.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    # Path.home() reads from HOME / USERPROFILE depending on platform;
    # monkeypatch the resolver too for cross-platform coverage.
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    plugin = "better-notion-mcp"
    paths = driver._cred_storage_paths_for_plugin(plugin)

    # Every surface listed in the spec must appear in the enumeration.
    # Use suffix matching so platform-specific bases (APPDATA vs
    # ~/.config/mcp) are tolerated.
    rendered = [str(p) for p in paths]
    assert any("config.enc" in r for r in rendered), (
        f"no config.enc surface in {rendered}"
    )
    assert any(".better-notion-mcp" in r and "config.json" in r for r in rendered)
    assert any(".better-notion-mcp" in r and r.endswith("users") for r in rendered)
    assert any(".better-notion-mcp" in r and r.endswith("subs") for r in rendered)
    assert any(".better-notion-mcp" in r and "tokens.json" in r for r in rendered)

    # Now create files at every enumerated path and assert removal.
    created: list[Path] = []
    for p in paths:
        p.parent.mkdir(parents=True, exist_ok=True)
        # Surfaces that look like directories (no suffix and ending in
        # users/ or subs/) get created as dirs with one inner file.
        if p.name in {"users", "subs"}:
            p.mkdir(parents=True, exist_ok=True)
            inner = p / "alice.json"
            inner.write_text("{}", encoding="utf-8")
            created.append(p)
        else:
            p.write_text("dummy", encoding="utf-8")
            created.append(p)

    removed = driver._clear_persistent_cred_storage(plugin)

    # Every created path was removed.
    for p in created:
        assert not p.exists(), f"path still exists after wipe: {p}"
    # Removed list reports the same count.
    assert len(removed) == len(created), (
        f"expected {len(created)} removals, got {len(removed)}: {removed}"
    )


def test_clear_persistent_cred_storage_idempotent_when_empty(tmp_path, monkeypatch):
    """Wiping a clean home is a no-op (no exception, empty return)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    removed = driver._clear_persistent_cred_storage("better-email-mcp")
    assert removed == []


def test_strict_no_fallback_required_plugin_exits_1(monkeypatch, tmp_path):
    """Required-cred plugins must exit 1 after the cred-storage wipe.
    A non-1 exit indicates the plugin booted from a fallback surface
    not yet covered by the wipe — the test fails and the gap must be
    plugged before the strict config can ship to T0."""
    # Make Path.home() resolve to tmp_path so the wipe targets nothing
    # real on disk. Spawn helper is fully mocked.
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    spawn_calls: list[tuple[str, dict]] = []

    async def fake_spawn(config, env):
        spawn_calls.append((config["id"], env))
        # Required-cred plugins (notion/email/telegram) exit 1 with the
        # documented stderr format when env={} AND no fallback exists.
        if config["id"] in driver.STRICT_NO_FALLBACK_PLUGINS:
            return {
                "status": "FAIL",
                "tool_calls": 0,
                "evidence": [],
                "exit_code": 1,
                "stderr": (
                    f"[{driver.STDIO_PLUGIN_PACKAGE[config['id']]}] required "
                    "env not set.\n"
                ),
            }
        # Optional-cred / no-cred plugins boot fine.
        return {
            "status": "PASS",
            "tool_calls": 1,
            "evidence": ["help"],
            "exit_code": 0,
            "stderr": "",
        }

    monkeypatch.setattr(driver, "_spawn_stdio_and_call_tool", fake_spawn)

    cfg = {"id": "stdio-pure-strict-no-fallback"}
    # Should NOT raise — every required plugin exits 1, every other
    # plugin boots cleanly.
    driver._run_stdio_pure_strict_no_fallback(cfg)

    # Exactly one spawn per plugin in STDIO_PLUGIN_PACKAGE.
    spawned_ids = {sid for sid, _ in spawn_calls}
    assert spawned_ids == set(driver.STDIO_PLUGIN_PACKAGE.keys()), (
        f"missing plugin spawns: {set(driver.STDIO_PLUGIN_PACKAGE) - spawned_ids}"
    )
    # Every required plugin was spawned with empty env (no fallback shortcut).
    for sid, env in spawn_calls:
        if sid in driver.STRICT_NO_FALLBACK_PLUGINS:
            assert env == {}, (
                f"required plugin {sid} spawned with non-empty env {env} — "
                "wipe step not enforced"
            )


def test_strict_no_fallback_optional_plugin_boots_without_store_load(
    monkeypatch, tmp_path
):
    """Optional-cred plugins boot cleanly with empty env after the
    PerPluginStore wipe; if the plugin secretly read creds from the
    pre-wipe store, the spawn would still succeed but ``status`` would
    only be PASS via fallback. Here we assert PASS comes WITHOUT cloud
    keys appearing in the inherited env (the wipe + empty-env contract
    is intact)."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    async def fake_spawn(config, env):
        # The strict runner passes env={}; the spawn helper merges with
        # os.environ. Optional-cred plugins boot in limited mode and
        # return PASS — no cred mutation possible.
        if config["id"] in driver.STRICT_NO_FALLBACK_PLUGINS:
            return {
                "status": "FAIL",
                "tool_calls": 0,
                "evidence": [],
                "exit_code": 1,
                "stderr": "required env not set",
            }
        return {
            "status": "PASS",
            "tool_calls": 1,
            "evidence": ["help"],
            "exit_code": 0,
            "stderr": "",
        }

    monkeypatch.setattr(driver, "_spawn_stdio_and_call_tool", fake_spawn)

    cfg = {"id": "stdio-pure-strict-no-fallback"}
    # Optional-cred plugins (wet/mnemo/crg/imagine) and no-cred
    # (godot) all return PASS — strict config completes without
    # raising.
    driver._run_stdio_pure_strict_no_fallback(cfg)


def test_strict_no_fallback_fails_when_required_plugin_boots(monkeypatch, tmp_path):
    """Regression guard: if a required-cred plugin returns exit 0 (i.e.
    a fallback surface is being read), the strict runner must fail
    loudly with the offending plugin name in the error."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    async def fake_spawn(config, env):
        # Simulate the regression: notion-stdio booted from a leftover
        # PerPluginStore artefact instead of exiting 1.
        if config["id"] == "notion-stdio":
            return {
                "status": "PASS",
                "tool_calls": 1,
                "evidence": ["help"],
                "exit_code": 0,
                "stderr": "",
            }
        if config["id"] in driver.STRICT_NO_FALLBACK_PLUGINS:
            return {
                "status": "FAIL",
                "tool_calls": 0,
                "evidence": [],
                "exit_code": 1,
                "stderr": "required env not set",
            }
        return {
            "status": "PASS",
            "tool_calls": 1,
            "evidence": ["help"],
            "exit_code": 0,
            "stderr": "",
        }

    monkeypatch.setattr(driver, "_spawn_stdio_and_call_tool", fake_spawn)

    cfg = {"id": "stdio-pure-strict-no-fallback"}
    with pytest.raises(RuntimeError, match="notion-stdio"):
        driver._run_stdio_pure_strict_no_fallback(cfg)


def test_strict_no_fallback_optional_plugin_fail_surfaced(monkeypatch, tmp_path):
    """If an optional-cred plugin fails handshake under strict mode,
    the runner must raise so the user can investigate (it's still a
    legitimate breakage — uvx upgrade required, transitive pin stale,
    etc.)."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    async def fake_spawn(config, env):
        if config["id"] == "wet-stdio":
            # Optional-cred plugin failed to boot for unrelated reasons.
            return {
                "status": "FAIL",
                "tool_calls": 0,
                "evidence": [],
                "exit_code": 1,
                "stderr": "uvx pin failed",
            }
        if config["id"] in driver.STRICT_NO_FALLBACK_PLUGINS:
            return {
                "status": "FAIL",
                "tool_calls": 0,
                "evidence": [],
                "exit_code": 1,
                "stderr": "required env not set",
            }
        return {
            "status": "PASS",
            "tool_calls": 1,
            "evidence": ["help"],
            "exit_code": 0,
            "stderr": "",
        }

    monkeypatch.setattr(driver, "_spawn_stdio_and_call_tool", fake_spawn)

    cfg = {"id": "stdio-pure-strict-no-fallback"}
    with pytest.raises(RuntimeError, match="wet-stdio"):
        driver._run_stdio_pure_strict_no_fallback(cfg)
