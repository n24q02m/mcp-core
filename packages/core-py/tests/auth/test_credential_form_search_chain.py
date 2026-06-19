"""Tests for the search-chain variant of the shared chain widget.

search-chain reuses the model-chain chip/drag/derive-keys UI but resolves
credential fields from an explicit ``providerKeys`` map (named backends) instead
of model-prefix inference, and customizes the empty-chain badge text.
"""

from mcp_core.auth.credential_form import _render_field, render_credential_form


def test_search_chain_renders_explicit_provider_keys_and_badge_attrs():
    field = {
        "key": "SEARCH_BACKENDS",
        "label": "Search providers",
        "type": "search-chain",
        "task": "search",
        "suggestedModels": ["searxng", "tavily", "brave", "exa"],
        "hasLocal": True,
        "providerKeys": {"tavily": "TAVILY_API_KEY", "brave": "BRAVE_API_KEY", "exa": "EXA_API_KEY"},
        "noun": "backends",
        "localLabel": "local SearXNG",
    }
    html = _render_field(field, "searxng,tavily")
    # Same hidden-CSV + widget container as model-chain.
    assert 'name="SEARCH_BACKENDS"' in html
    assert 'type="hidden"' in html
    assert 'value="searxng,tavily"' in html
    assert 'data-model-chain="search"' in html
    assert 'data-has-local="true"' in html
    # Named backends appear as suggestions.
    assert "tavily" in html and "brave" in html and "exa" in html
    # search-chain-only data attributes.
    assert "data-provider-keys=" in html
    assert "TAVILY_API_KEY" in html
    assert 'data-noun="backends"' in html
    assert 'data-local-label="local SearXNG"' in html


def test_model_chain_omits_search_chain_attrs():
    # Regression guard: a model-chain field must NOT gain the new attributes,
    # so existing embed/rerank/llm widgets render byte-for-byte unchanged.
    field = {
        "key": "EMBEDDING_MODELS",
        "label": "Embedding models",
        "type": "model-chain",
        "task": "embedding",
        "suggestedModels": ["jina_ai/jina-embeddings-v5-text-small"],
        "hasLocal": True,
    }
    html = _render_field(field, "")
    assert "data-provider-keys" not in html
    assert "data-noun" not in html
    assert "data-local-label" not in html


def test_full_form_search_chain_with_derived_backend_keys():
    schema = {
        "server": "wet",
        "displayName": "wet",
        "fields": [
            {
                "key": "SEARCH_BACKENDS",
                "label": "Search providers",
                "type": "search-chain",
                "task": "search",
                "suggestedModels": ["searxng", "tavily", "brave", "exa"],
                "hasLocal": True,
                "providerKeys": {"tavily": "TAVILY_API_KEY", "brave": "BRAVE_API_KEY", "exa": "EXA_API_KEY"},
                "noun": "backends",
                "localLabel": "local SearXNG",
            },
            {"key": "TAVILY_API_KEY", "label": "Tavily", "type": "password", "derived": True},
            {"key": "BRAVE_API_KEY", "label": "Brave", "type": "password", "derived": True},
            {"key": "EXA_API_KEY", "label": "Exa", "type": "password", "derived": True},
        ],
    }
    html = render_credential_form(schema, submit_url="/authorize")
    # Derived backend-key fields are present + hidden until referenced.
    assert 'data-provider-key="TAVILY_API_KEY"' in html
    assert 'data-provider-key="EXA_API_KEY"' in html
    # The generalized derive-keys logic (explicit-map branch) is shipped.
    assert "data-provider-keys" in html
    assert "deriveKeys" in html
    # The widget JS reads the explicit map before prefix inference.
    assert "Object.prototype.hasOwnProperty" in html
