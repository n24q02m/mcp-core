from mcp_core.auth.credential_form import _render_field


def test_model_chain_renders_widget_container_and_hidden_csv():
    field = {
        "key": "EMBEDDING_MODELS",
        "label": "Embedding models",
        "type": "model-chain",
        "task": "embedding",
        "suggestedModels": ["jina_ai/jina-embeddings-v5-text-small", "gemini/gemini-embedding-001"],
        "hasLocal": True,
    }
    html = _render_field(field, "gemini/gemini-embedding-001")
    assert 'name="EMBEDDING_MODELS"' in html
    assert 'type="hidden"' in html
    assert 'class="field-input"' in html
    assert 'value="gemini/gemini-embedding-001"' in html
    assert 'data-model-chain="embedding"' in html
    assert 'data-has-local="true"' in html
    assert "jina_ai/jina-embeddings-v5-text-small" in html


def test_derived_key_field_hidden_with_provider_marker():
    field = {"key": "GEMINI_API_KEY", "label": "Gemini API Key", "type": "password", "derived": True}
    html = _render_field(field, "")
    assert 'data-provider-key="GEMINI_API_KEY"' in html
    assert "display:none" in html.replace(" ", "")
    assert 'name="GEMINI_API_KEY"' in html


def test_plain_password_field_unchanged():
    field = {"key": "GITHUB_TOKEN", "label": "GitHub", "type": "password"}
    html = _render_field(field, "")
    assert 'type="password"' in html
    assert "data-model-chain" not in html
    assert "data-provider-key" not in html


def test_full_form_with_model_chain_renders_script_and_map():
    from mcp_core.auth.credential_form import render_credential_form

    schema = {
        "server": "demo",
        "displayName": "Demo",
        "fields": [
            {
                "key": "EMBEDDING_MODELS",
                "label": "Embedding",
                "type": "model-chain",
                "task": "embedding",
                "suggestedModels": ["jina_ai/jina-embeddings-v5-text-small"],
                "hasLocal": True,
            },
            {"key": "JINA_AI_API_KEY", "label": "Jina", "type": "password", "derived": True},
        ],
    }
    html = render_credential_form(schema, submit_url="/authorize")
    assert "PROVIDER_KEY" in html
    assert "JINA_AI_API_KEY" in html
    assert 'data-model-chain="embedding"' in html
    assert "deriveKeys" in html


# --- F2: searchable combobox (free-text + filter + catalog-backed) ---------


def _embedding_field():
    return {
        "key": "EMBEDDING_MODELS",
        "label": "Embedding models",
        "type": "model-chain",
        "task": "embedding",
        "suggestedModels": ["jina_ai/jina-embeddings-v5-text-small"],
        "hasLocal": True,
    }


def test_widget_accepts_free_typed_model_not_in_suggested():
    """The Enter handler must accept any shape-valid provider/model, not only
    the curated suggestedModels (the old hard reject is removed)."""
    from mcp_core.auth.credential_form import _MODEL_CHAIN_SCRIPT

    # The old cage: reject anything not in the suggested list.
    assert "if (suggested.indexOf(m) === -1) { return; }" not in _MODEL_CHAIN_SCRIPT
    # The new gate: a loose shape check that lets free-typed models through.
    assert "looksLikeModel" in _MODEL_CHAIN_SCRIPT


def test_widget_filters_dropdown_as_you_type():
    """An ``input`` listener re-filters the dropdown by the typed substring."""
    from mcp_core.auth.credential_form import _MODEL_CHAIN_SCRIPT

    assert 'addEventListener("input"' in _MODEL_CHAIN_SCRIPT


def test_model_chain_dropdown_includes_catalog_models(monkeypatch):
    """The model-chain dropdown is backed by catalog.list_models so a user can
    search the real provider/model space, not just the server's curated few."""
    import mcp_core.llm.catalog as catalog
    from mcp_core.auth.credential_form import _render_field

    monkeypatch.setattr(
        catalog,
        "list_models",
        lambda **kw: [
            {"model": "openai/text-embedding-3-large", "provider": "openai", "mode": "embedding"},
            {"model": "cohere/embed-multilingual-v3.0", "provider": "cohere", "mode": "embedding"},
        ],
    )
    html = _render_field(_embedding_field(), "")
    assert "data-catalog=" in html
    assert "openai/text-embedding-3-large" in html
    assert "cohere/embed-multilingual-v3.0" in html


def test_model_chain_catalog_graceful_when_unavailable(monkeypatch):
    """If the catalog (litellm) is unavailable, render still succeeds with an
    empty catalog rather than raising."""
    import mcp_core.llm.catalog as catalog
    from mcp_core.auth.credential_form import _render_field

    def _boom(**kw):
        raise RuntimeError("litellm not installed")

    monkeypatch.setattr(catalog, "list_models", _boom)
    html = _render_field(_embedding_field(), "")
    assert 'data-catalog="[]"' in html
    # The curated suggestion is still present (catalog failure is non-fatal).
    assert "jina_ai/jina-embeddings-v5-text-small" in html


def test_search_chain_has_no_catalog():
    """search-chain uses explicit named backends (searxng/tavily), not litellm
    models — it must NOT fetch a model catalog."""
    from mcp_core.auth.credential_form import _render_field

    field = {
        "key": "SEARCH_BACKENDS",
        "label": "Search backends",
        "type": "search-chain",
        "task": "search",
        "suggestedModels": ["searxng", "tavily"],
        "providerKeys": {"tavily": "TAVILY_API_KEY"},
        "hasLocal": True,
    }
    html = _render_field(field, "")
    assert 'data-catalog="[]"' in html


# --- F2-relay-search: full catalog (generate task + un-sliced understand) ----


def test_generate_task_catalog_is_non_empty():
    """imagine's GENERATE_MODELS field uses task='generate'. Before the fix the
    'generate' key was absent from _TASK_CATALOG_MODES so the catalog was empty
    and only the 9 hardcoded suggestedModels were searchable. The generate task
    must map to litellm's image/video generation mode(s) so the dropdown is
    backed by the real catalog."""
    from mcp_core.auth.credential_form import _catalog_models_for_task

    catalog = _catalog_models_for_task("generate")
    assert catalog, "generate task must yield a non-empty model catalog"


def test_understand_catalog_covers_beyond_first_100_alphabetical():
    """The understand (chat) catalog was capped at 100 alphabetical models, so
    later-alphabet models (e.g. azure_ai/deepseek-*) fell off the slice and were
    unsearchable. The catalog must cover the full list, not a 100-slice."""
    from mcp_core.auth.credential_form import _catalog_models_for_task

    catalog = _catalog_models_for_task("understand")
    # deepseek chat models sort well past the first 100 entries; their presence
    # proves the slice no longer truncates the catalog.
    assert any("deepseek" in m.lower() for m in catalog), (
        "understand catalog must include later-alphabet models (e.g. deepseek), "
        "i.e. it must not be capped at the first 100 alphabetical entries"
    )
