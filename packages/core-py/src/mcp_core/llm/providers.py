"""Canonical model-prefix -> credential-env-var mapping.

Single source of truth shared by:
  - the relay "model-chain" widget (derive-keys, injected as JSON),
  - per-server docs (provider->key table),
  - per-server config reading.

litellm key convention: each provider reads ``<PROVIDER>_API_KEY`` from env.
A bare model name (no "/") is an OpenAI model by litellm convention.
"""

from __future__ import annotations

PROVIDER_KEY_ENV: dict[str, str] = {
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "jina_ai": "JINA_AI_API_KEY",
    "cohere": "COHERE_API_KEY",
    "xai": "XAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}

CURATED_PROVIDERS = frozenset(PROVIDER_KEY_ENV)


def provider_of_model(model: str) -> str:
    """Provider prefix of a litellm model string; bare name -> 'openai'."""
    model = model.strip()
    if "/" in model:
        return model.split("/", 1)[0]
    return "openai"


def key_env_for_model(model: str) -> str:
    """The ``<PROVIDER>_API_KEY`` env var a model needs.

    Curated providers use the canonical table; any other provider falls back
    to the deterministic ``<UPPERCASE_PREFIX>_API_KEY`` litellm convention.
    """
    provider = provider_of_model(model)
    if provider in PROVIDER_KEY_ENV:
        return PROVIDER_KEY_ENV[provider]
    return f"{provider.upper()}_API_KEY"
