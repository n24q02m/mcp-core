"""Tests for the capability provider-chain primitives (mcp_core.chains)."""

from __future__ import annotations

import pytest

from mcp_core.chains import (
    Backend,
    local_enabled_from_env,
    resolve_backend,
    run_with_fallback,
)


# --- Backend enum --------------------------------------------------------


def test_backend_members_equal_their_str_value():
    assert Backend.CLOUD == "cloud"
    assert Backend.LOCAL == "local"
    assert Backend.UNAVAILABLE == "unavailable"
    # StrEnum is usable anywhere a str is expected.
    assert f"{Backend.CLOUD}" == "cloud"


# --- local_enabled_from_env ---------------------------------------------


def test_local_enabled_none_toggle_always_enabled():
    assert local_enabled_from_env(None) is True


def test_local_enabled_absent_env_defaults_enabled():
    assert local_enabled_from_env("DISABLE_LOCAL_EMBED", environ={}) is True


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "Yes", "on", " on ", "On"])
def test_local_disabled_for_truthy_values(value):
    env = {"DISABLE_LOCAL_EMBED": value}
    assert local_enabled_from_env("DISABLE_LOCAL_EMBED", environ=env) is False


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "anything"])
def test_local_enabled_for_falsey_or_unknown_values(value):
    env = {"DISABLE_LOCAL_EMBED": value}
    assert local_enabled_from_env("DISABLE_LOCAL_EMBED", environ=env) is True


def test_local_enabled_reads_os_environ_by_default(monkeypatch):
    monkeypatch.setenv("DISABLE_LOCAL_RERANK", "true")
    assert local_enabled_from_env("DISABLE_LOCAL_RERANK") is False
    monkeypatch.delenv("DISABLE_LOCAL_RERANK", raising=False)
    assert local_enabled_from_env("DISABLE_LOCAL_RERANK") is True


# --- resolve_backend -----------------------------------------------------


def test_resolve_cloud_when_chain_present_regardless_of_local():
    # A configured cloud chain always wins, even with local disabled.
    assert resolve_backend(has_cloud_chain=True, local_enabled=True) is Backend.CLOUD
    assert resolve_backend(has_cloud_chain=True, local_enabled=False) is Backend.CLOUD


def test_resolve_local_when_no_chain_and_local_enabled():
    assert resolve_backend(has_cloud_chain=False, local_enabled=True) is Backend.LOCAL


def test_resolve_unavailable_when_no_chain_and_local_disabled():
    # The case the old "cloud if chain else local" rule could not express.
    assert resolve_backend(has_cloud_chain=False, local_enabled=False) is Backend.UNAVAILABLE


def test_resolve_unavailable_when_no_local_leg_and_no_chain():
    # llm / captcha: no local leg at all.
    assert resolve_backend(has_cloud_chain=False, local_enabled=True, has_local_leg=False) is Backend.UNAVAILABLE


def test_resolve_cloud_for_no_local_leg_with_chain():
    assert resolve_backend(has_cloud_chain=True, local_enabled=True, has_local_leg=False) is Backend.CLOUD


# --- run_with_fallback ---------------------------------------------------


async def _ok(value):
    return value


async def _boom():
    raise RuntimeError("provider failed")


async def test_fallback_returns_first_non_empty():
    result = await run_with_fallback([lambda: _ok(["a"]), lambda: _ok(["b"])])
    assert result == ["a"]


async def test_fallback_skips_empty_results():
    result = await run_with_fallback([lambda: _ok([]), lambda: _ok(["b"])])
    assert result == ["b"]


async def test_fallback_skips_errors_and_invokes_on_error():
    seen: list[tuple[int, str]] = []
    result = await run_with_fallback(
        [lambda: _boom(), lambda: _ok("html")],
        on_error=lambda idx, exc: seen.append((idx, str(exc))),
    )
    assert result == "html"
    assert seen == [(0, "provider failed")]


async def test_fallback_returns_none_when_all_empty():
    result = await run_with_fallback([lambda: _ok([]), lambda: _ok("")])
    assert result is None


async def test_fallback_returns_none_when_all_error():
    result = await run_with_fallback([lambda: _boom(), lambda: _boom()])
    assert result is None


async def test_fallback_custom_is_empty_predicate():
    # Treat the sentinel "EMPTY" string as empty even though it is truthy.
    result = await run_with_fallback(
        [lambda: _ok("EMPTY"), lambda: _ok("real")],
        is_empty=lambda r: r == "EMPTY",
    )
    assert result == "real"


async def test_fallback_empty_provider_list_returns_none():
    assert await run_with_fallback([]) is None
