"""Transparent per-provider key rotation in the async llm dispatch.

Patches the real ``litellm`` module attribute (dispatch resolves it via
``_get_litellm()`` at call time), mirroring tests/llm/test_dispatch.py.
"""

import pytest

litellm = pytest.importorskip("litellm")

from mcp_core.llm import aembedding  # noqa: E402


class _RL(Exception):
    def __init__(self):
        self.status_code = 429


async def test_aembedding_rotates_to_second_key_on_429(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "bad,good")
    used = []

    async def fake(model, input, **kw):
        used.append(kw.get("api_key"))
        if kw.get("api_key") == "bad":
            raise _RL()
        return {"data": [{"embedding": [0.0]}]}

    monkeypatch.setattr(litellm, "aembedding", fake)
    out = await aembedding(model="gemini/gemini-embedding-001", input=["x"])
    assert out["data"][0]["embedding"] == [0.0]
    assert used == ["bad", "good"]  # rotated


async def test_aembedding_single_key_unchanged(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "solo")
    used = []

    async def fake(model, input, **kw):
        used.append(kw.get("api_key"))
        return {"data": []}

    monkeypatch.setattr(litellm, "aembedding", fake)
    await aembedding(model="gemini/gemini-embedding-001", input=["x"])
    # single key path forwards nothing extra (litellm reads env itself) -> api_key None
    assert used == [None]
