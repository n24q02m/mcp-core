"""Tests for mcp_core.llm.dispatch — needs litellm installed (extras leg).

Registry modes pinned below verified against litellm 1.88.1:
gemini/veo-3.1-generate-preview=video_generation, dall-e-3=image_generation,
cohere/rerank-english-v3.0=rerank (bare-name fallback), gpt-4o-mini=chat,
text-embedding-3-large=embedding; jina_ai/jina-reranker-v3, ollama_chat/llama3
and openai/custom are registry-missing (graceful passthrough).
"""

import socket
from unittest.mock import AsyncMock, MagicMock

import pytest

litellm = pytest.importorskip("litellm")

from mcp_core.http import SSRFBlockedError  # noqa: E402
from mcp_core.llm import (  # noqa: E402
    ModelCapabilityError,
    acompletion,
    aembedding,
    aimage_generation,
    arerank,
    avideo_generation,
    completion,
    embedding,
    rerank,
)


def _fake_getaddrinfo(ip: str):
    def fake(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 443))]

    return fake


async def test_acompletion_passthrough(monkeypatch):
    mock = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(litellm, "acompletion", mock)
    result = await acompletion(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}])
    assert result == {"ok": True}
    assert mock.call_args.kwargs["model"] == "gpt-4o-mini"


async def test_acompletion_rejects_wrong_mode(monkeypatch):
    mock = AsyncMock()
    monkeypatch.setattr(litellm, "acompletion", mock)
    with pytest.raises(ModelCapabilityError):
        await acompletion(
            model="text-embedding-3-large",
            messages=[{"role": "user", "content": "hi"}],
        )
    mock.assert_not_called()


async def test_acompletion_vets_api_base(monkeypatch):
    mock = AsyncMock()
    monkeypatch.setattr(litellm, "acompletion", mock)
    monkeypatch.setenv("PUBLIC_URL", "https://srv.example.com")  # multi-user
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    with pytest.raises(SSRFBlockedError):
        await acompletion(
            model="openai/custom",
            messages=[{"role": "user", "content": "hi"}],
            api_base="http://localhost:8000/v1",
        )
    mock.assert_not_called()


async def test_acompletion_allows_loopback_api_base_single_user(monkeypatch):
    mock = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(litellm, "acompletion", mock)
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    result = await acompletion(
        model="ollama_chat/llama3",
        messages=[{"role": "user", "content": "hi"}],
        api_base="http://localhost:11434",
    )
    assert result == {"ok": True}


async def test_acompletion_forwards_api_key_and_api_base(monkeypatch):
    mock = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(litellm, "acompletion", mock)
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    await acompletion(
        model="openai/custom",
        messages=[{"role": "user", "content": "hi"}],
        api_base="https://example.com/v1",
        api_key="sk-test",
    )
    kw = mock.call_args.kwargs
    assert kw["api_key"] == "sk-test"
    assert kw["api_base"] == "https://example.com/v1"


async def test_arerank_omits_none_credentials(monkeypatch):
    # Explicit api_key=None/api_base=None through litellm's **kwargs path is
    # Pydantic field-SET (survives exclude_unset) and suppresses env fallback.
    mock = AsyncMock(return_value={"results": []})
    monkeypatch.setattr(litellm, "arerank", mock)
    await arerank(model="jina_ai/jina-reranker-v3", query="q", documents=["a"])
    kw = mock.call_args.kwargs
    assert "api_key" not in kw
    assert "api_base" not in kw


async def test_aembedding_passthrough(monkeypatch):
    mock = AsyncMock(return_value={"data": []})
    monkeypatch.setattr(litellm, "aembedding", mock)
    await aembedding(model="text-embedding-3-large", input=["x"], dimensions=768)
    assert mock.call_args.kwargs["dimensions"] == 768


async def test_arerank_passthrough(monkeypatch):
    mock = AsyncMock(return_value={"results": []})
    monkeypatch.setattr(litellm, "arerank", mock)
    await arerank(model="jina_ai/jina-reranker-v3", query="q", documents=["a"], top_n=1)
    assert mock.call_args.kwargs["top_n"] == 1


async def test_aimage_generation_passthrough(monkeypatch):
    mock = AsyncMock(return_value={"data": []})
    monkeypatch.setattr(litellm, "aimage_generation", mock)
    await aimage_generation(model="dall-e-3", prompt="a cat")
    mock.assert_awaited_once()


async def test_avideo_generation_passthrough(monkeypatch):
    mock = AsyncMock(return_value={"id": "vid_1"})
    monkeypatch.setattr(litellm, "avideo_generation", mock)
    await avideo_generation(model="gemini/veo-3.1-generate-preview", prompt="a dog")
    mock.assert_awaited_once()


# --- Sync mirrors ---


def test_completion_sync_passthrough(monkeypatch):
    mock = MagicMock(return_value={"ok": True})
    monkeypatch.setattr(litellm, "completion", mock)
    result = completion(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}])
    assert result == {"ok": True}


def test_embedding_sync_rejects_wrong_mode(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(litellm, "embedding", mock)
    with pytest.raises(ModelCapabilityError):
        embedding(model="gpt-4o-mini", input=["x"])
    mock.assert_not_called()


def test_rerank_sync_vets_api_base(monkeypatch):
    mock = MagicMock()
    monkeypatch.setattr(litellm, "rerank", mock)
    monkeypatch.setenv("PUBLIC_URL", "https://srv.example.com")
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("10.0.0.5"))
    with pytest.raises(SSRFBlockedError):
        rerank(
            model="cohere/rerank-english-v3.0",
            query="q",
            documents=["a"],
            api_base="http://internal.lan/v1",
        )
    mock.assert_not_called()


async def test_acompletion_routes_vertex_express_bypassing_litellm(monkeypatch):
    # litellm.acompletion MUST NOT be called for a vertex_express model.
    litellm_mock = AsyncMock()
    monkeypatch.setattr(litellm, "acompletion", litellm_mock)

    express_mock = AsyncMock(return_value="EXPRESS_RESULT")
    monkeypatch.setattr("mcp_core.llm.dispatch.acompletion_express", express_mock)
    result = await acompletion(
        model="vertex_express/gemini-2.5-flash",
        messages=[{"role": "user", "content": "hi"}],
        api_key="AQ.key",
    )
    assert result == "EXPRESS_RESULT"
    litellm_mock.assert_not_called()
    assert express_mock.call_args.kwargs["model"] == "vertex_express/gemini-2.5-flash"
    assert express_mock.call_args.kwargs["api_key"] == "AQ.key"


async def test_acompletion_non_express_still_uses_litellm(monkeypatch):
    litellm_mock = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(litellm, "acompletion", litellm_mock)
    express_mock = AsyncMock()
    monkeypatch.setattr("mcp_core.llm.dispatch.acompletion_express", express_mock)
    result = await acompletion(
        model="gemini/gemini-2.5-flash",
        messages=[{"role": "user", "content": "hi"}],
    )
    assert result == {"ok": True}
    express_mock.assert_not_called()
    litellm_mock.assert_awaited_once()


def test_completion_sync_routes_vertex_express(monkeypatch):
    litellm_mock = MagicMock()
    monkeypatch.setattr(litellm, "completion", litellm_mock)
    express_mock = MagicMock(return_value="SYNC_EXPRESS")
    monkeypatch.setattr("mcp_core.llm.dispatch.completion_express", express_mock)
    result = completion(
        model="vertex_express/gemini-2.5-flash",
        messages=[{"role": "user", "content": "hi"}],
        api_key="AQ.key",
    )
    assert result == "SYNC_EXPRESS"
    litellm_mock.assert_not_called()
