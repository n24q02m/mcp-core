"""Tests for mcp_core.llm.catalog — needs litellm installed (extras leg).

Model names pinned below (gpt-4o-mini, text-embedding-3-large,
claude-haiku-4-5) verified present in the litellm 1.88.1 registry — if a
litellm bump drifts these keys, update the tests accordingly.
"""

import pytest

litellm = pytest.importorskip("litellm")

from mcp_core.llm import (  # noqa: E402
    ModelCapabilityError,
    check_capability,
    list_models,
    suggest_models,
    supports_vision,
)


def test_check_capability_pass_for_chat_model():
    check_capability("gpt-4o-mini", ("chat",))  # registry mode=chat


def test_check_capability_raises_on_mode_mismatch():
    with pytest.raises(ModelCapabilityError, match="embedding"):
        check_capability("text-embedding-3-large", ("chat",))


def test_check_capability_graceful_on_registry_missing():
    # Verified registry-missing models must pass through (spec D3):
    check_capability("jina_ai/jina-embeddings-v5-text-small", ("embedding",))
    check_capability("xai/grok-4-fast", ("chat",))


def test_check_capability_falls_back_to_bare_name():
    # Registry keys anthropic models WITHOUT provider prefix.
    check_capability("anthropic/claude-haiku-4-5", ("chat",))


def test_check_capability_passthrough_on_modeless_entry(monkeypatch):
    # Registry metadata entries (e.g. fireworks-ai-* pricing tiers) are dicts
    # WITHOUT a "mode" key — these must pass through, not raise. Fake entry
    # instead of a real fireworks key: deterministic across litellm bumps.
    monkeypatch.setitem(litellm.model_cost, "fake-no-mode-entry", {"input_cost_per_token": 0})
    check_capability("fake-no-mode-entry", ("chat",))


def test_check_capability_error_message_without_hints(monkeypatch):
    for var in (
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "XAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "COHERE_API_KEY",
        "CO_API_KEY",
        "JINA_AI_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ModelCapabilityError) as excinfo:
        check_capability("text-embedding-3-large", ("nonexistent_mode_xyz",))
    message = str(excinfo.value)
    assert "Compatible examples:" not in message
    assert message.endswith(".")


def test_supports_vision_known_and_unknown():
    assert supports_vision("gpt-4o-mini") is True
    assert supports_vision("totally/unknown-model-xyz") is None


def test_list_models_filters_by_mode():
    models = list_models(modes=("embedding",), configured_only=False, limit=10)
    assert models
    assert all(m["mode"] == "embedding" for m in models)


def test_list_models_configured_only(monkeypatch):
    for var in (
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "XAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "COHERE_API_KEY",
        "CO_API_KEY",
        "JINA_AI_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    models = list_models(modes=("chat",), configured_only=True, limit=50)
    assert models
    assert all(m["provider"] == "openai" for m in models)


def test_suggest_models_returns_names():
    names = suggest_models(("video_generation",), limit=3)
    assert 0 < len(names) <= 3
    assert all(isinstance(n, str) for n in names)
