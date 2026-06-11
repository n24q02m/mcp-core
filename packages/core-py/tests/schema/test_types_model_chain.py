from mcp_core.schema.types import ConfigField


def test_model_chain_field_accepts_new_keys():
    f: ConfigField = {
        "key": "EMBEDDING_MODELS",
        "label": "Embedding models",
        "type": "model-chain",
        "task": "embedding",
        "suggestedModels": ["jina_ai/jina-embeddings-v5-text-small", "gemini/gemini-embedding-001"],
        "hasLocal": True,
    }
    assert f["task"] == "embedding"
    assert f["hasLocal"] is True
    assert "gemini/gemini-embedding-001" in f["suggestedModels"]


def test_derived_key_field():
    f: ConfigField = {"key": "GEMINI_API_KEY", "type": "password", "derived": True}
    assert f["derived"] is True
