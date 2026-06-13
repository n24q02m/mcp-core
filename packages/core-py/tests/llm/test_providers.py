from mcp_core.llm.providers import (
    CURATED_PROVIDERS,
    PROVIDER_KEY_ENV,
    key_env_for_model,
    provider_of_model,
)


def test_provider_of_model_with_prefix():
    assert provider_of_model("jina_ai/jina-embeddings-v5-text-small") == "jina_ai"
    assert provider_of_model("gemini/gemini-3-flash-preview") == "gemini"
    assert provider_of_model("xai/grok-4-fast") == "xai"


def test_provider_of_model_bare_is_openai():
    assert provider_of_model("text-embedding-3-large") == "openai"
    assert provider_of_model("gpt-4o-mini") == "openai"


def test_key_env_for_curated_providers():
    assert key_env_for_model("gemini/x") == "GEMINI_API_KEY"
    assert key_env_for_model("jina_ai/x") == "JINA_AI_API_KEY"
    assert key_env_for_model("cohere/x") == "COHERE_API_KEY"
    assert key_env_for_model("xai/x") == "XAI_API_KEY"
    assert key_env_for_model("anthropic/x") == "ANTHROPIC_API_KEY"
    assert key_env_for_model("text-embedding-3-large") == "OPENAI_API_KEY"


def test_key_env_for_uncurated_provider_falls_back_to_convention():
    assert key_env_for_model("mistral/mistral-large") == "MISTRAL_API_KEY"


def test_curated_providers_set():
    assert CURATED_PROVIDERS == frozenset(
        {"gemini", "openai", "jina_ai", "cohere", "xai", "anthropic", "vertex_express"}
    )
    for p in CURATED_PROVIDERS:
        assert p in PROVIDER_KEY_ENV


def test_vertex_express_provider_key_env():
    from mcp_core.llm.providers import PROVIDER_KEY_ENV, key_env_for_model, provider_of_model

    assert PROVIDER_KEY_ENV["vertex_express"] == "GOOGLE_VERTEX_EXPRESS_API_KEY"
    assert provider_of_model("vertex_express/gemini-2.5-flash") == "vertex_express"
    assert key_env_for_model("vertex_express/gemini-2.5-flash") == "GOOGLE_VERTEX_EXPRESS_API_KEY"


def test_vertex_express_in_catalog_provider_env_keys():
    from mcp_core.llm.catalog import _PROVIDER_ENV_KEYS

    assert _PROVIDER_ENV_KEYS["GOOGLE_VERTEX_EXPRESS_API_KEY"] == "vertex_express"
