import mcp_core.llm.provider_catalog as pc

_JINA_SAMPLE = {
    "data": [
        {
            "id": "jina-ai/jina-embeddings-v5-text-small",
            "name": "jina-embeddings-v5-text-small",
            "output_modalities": ["embeddings"],
        },
        {"id": "jina-ai/jina-reranker-v3", "name": "jina-reranker-v3", "output_modalities": ["text"]},
        {"id": "jina-ai/jina-colbert-v2", "name": "jina-colbert-v2", "output_modalities": ["embeddings"]},
        {"id": "jina-ai/jina-vlm", "name": "jina-vlm", "output_modalities": ["text"]},
        {"id": "jina-ai/reader-lm-1.5b", "name": "reader-lm-1.5b", "output_modalities": ["text"]},
    ]
}


def _patch_fetch(monkeypatch, payload=_JINA_SAMPLE):
    calls = {"n": 0}

    def _fake(url, timeout):
        calls["n"] += 1
        return payload

    monkeypatch.setattr(pc, "_fetch_json", _fake)
    pc._CACHE.clear()
    return calls


def test_jina_embedding_models_are_prefixed_and_filtered(monkeypatch):
    _patch_fetch(monkeypatch)
    out = pc.provider_catalog_models("embedding")
    assert "jina_ai/jina-embeddings-v5-text-small" in out  # hyphen jina-ai/ -> underscore jina_ai/
    assert "jina_ai/jina-colbert-v2" in out  # output_modalities contains 'embeddings'
    assert "jina_ai/jina-reranker-v3" not in out  # rerank, not embedding
    assert "jina_ai/jina-vlm" not in out  # reader/vlm excluded
    assert all(m.startswith("jina_ai/") for m in out)


def test_jina_rerank_models_by_name(monkeypatch):
    _patch_fetch(monkeypatch)
    out = pc.provider_catalog_models("rerank")
    assert "jina_ai/jina-reranker-v3" in out
    assert "jina_ai/jina-colbert-v2" in out  # name matches /reranker|colbert/
    assert "jina_ai/jina-embeddings-v5-text-small" not in out
    assert "jina_ai/reader-lm-1.5b" not in out


def test_non_embed_rerank_task_returns_empty(monkeypatch):
    _patch_fetch(monkeypatch)
    assert pc.provider_catalog_models("chat") == []
    assert pc.provider_catalog_models("generate") == []


def test_result_is_cached(monkeypatch):
    calls = _patch_fetch(monkeypatch)
    pc.provider_catalog_models("embedding")
    pc.provider_catalog_models("rerank")
    assert calls["n"] == 1  # one upstream fetch, served from cache for the second task


def test_fetch_failure_falls_back_to_static(monkeypatch):
    def _boom(url, timeout):
        raise RuntimeError("network down")

    monkeypatch.setattr(pc, "_fetch_json", _boom)
    pc._CACHE.clear()
    emb = pc.provider_catalog_models("embedding")
    rer = pc.provider_catalog_models("rerank")
    assert "jina_ai/jina-embeddings-v5-text-small" in emb  # static fallback, never raises
    assert "jina_ai/jina-reranker-v3" in rer
