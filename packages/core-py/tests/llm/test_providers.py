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
    assert CURATED_PROVIDERS == frozenset({"gemini", "openai", "jina_ai", "cohere", "xai", "anthropic"})
    for p in CURATED_PROVIDERS:
        assert p in PROVIDER_KEY_ENV
