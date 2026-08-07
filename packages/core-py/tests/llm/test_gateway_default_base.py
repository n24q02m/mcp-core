"""Tests for the stack gateway default in mcp_core.llm.dispatch.

The contract: when no ``api_base`` is supplied by the caller, dispatch falls
back to the base URL configured for the stack (``MCP_LLM_GATEWAY_BASE``). An
explicit ``api_base`` always wins, and with nothing configured the old
behaviour is preserved byte-for-byte (no ``api_base`` key reaches litellm).

All URLs here are placeholders; DNS is faked so nothing is resolved for real.
"""

import socket

import pytest

litellm = pytest.importorskip("litellm")

from mcp_core.llm import acompletion  # noqa: E402

_GATEWAY_ENV = "MCP_LLM_GATEWAY_BASE"
_GATEWAY_BASE = "https://gateway.invalid/v1"
_CALLER_BASE = "https://caller.invalid/v1"


def _fake_getaddrinfo(ip: str):
    def fake(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 443))]

    return fake


@pytest.fixture
def seen(monkeypatch):
    """Capture the kwargs dispatch hands to litellm, single-user mode."""
    captured: dict = {}

    async def fake_acompletion(**kwargs):
        captured.update(kwargs)
        return {"ok": True}

    monkeypatch.setattr(litellm, "acompletion", fake_acompletion)
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    return captured


async def test_call_without_api_base_uses_the_stack_gateway(seen, monkeypatch):
    monkeypatch.setenv(_GATEWAY_ENV, _GATEWAY_BASE)
    await acompletion(model="openai/custom", messages=[{"role": "user", "content": "hi"}])
    assert seen["api_base"] == _GATEWAY_BASE


async def test_explicit_api_base_still_wins(seen, monkeypatch):
    monkeypatch.setenv(_GATEWAY_ENV, _GATEWAY_BASE)
    await acompletion(
        model="openai/custom",
        messages=[{"role": "user", "content": "hi"}],
        api_base=_CALLER_BASE,
    )
    assert seen["api_base"] == _CALLER_BASE


async def test_no_gateway_configured_keeps_the_old_behaviour(seen, monkeypatch):
    monkeypatch.delenv(_GATEWAY_ENV, raising=False)
    await acompletion(model="openai/custom", messages=[{"role": "user", "content": "hi"}])
    assert "api_base" not in seen
