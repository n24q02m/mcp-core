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
#
# These exercise the catalog WIRING (task -> mode mapping + un-capped limit
# passthrough) via a monkeypatched ``list_models``, so they are deterministic
# and do NOT require the optional ``[llm]`` extra (litellm). That matters
# because the e2e-t0 leg runs the suite without the extra, where the real
# catalog is empty by design (graceful fallback).


def test_generate_task_is_mapped_to_generation_modes(monkeypatch):
    """imagine's GENERATE_MODELS field uses task='generate'. Before the fix the
    'generate' key was absent from _TASK_CATALOG_MODES so the catalog was empty
    and only the curated suggestedModels were searchable. The generate task must
    map to litellm's image/video generation mode(s) and flow models through."""
    import mcp_core.llm.catalog as catalog_mod
    from mcp_core.auth.credential_form import _TASK_CATALOG_MODES, _catalog_models_for_task

    modes = _TASK_CATALOG_MODES.get("generate")
    assert modes, "generate task must be mapped to litellm generation mode(s)"
    assert "image_generation" in modes
    assert "video_generation" in modes

    captured: dict = {}

    def _fake_list_models(**kw):
        captured.update(kw)
        return [{"model": "openai/dall-e-3", "provider": "openai", "mode": "image_generation"}]

    monkeypatch.setattr(catalog_mod, "list_models", _fake_list_models)
    result = _catalog_models_for_task("generate")
    assert result == ["openai/dall-e-3"]
    assert captured["modes"] == modes


def test_catalog_is_not_capped_at_100(monkeypatch):
    """The understand (chat) catalog was capped at 100 alphabetical models, so
    later-alphabet models (e.g. azure_ai/deepseek-*) fell off the slice and were
    unsearchable. The catalog limit must cover the full registry (a few thousand
    models), and every model the registry returns must survive to the dropdown."""
    import mcp_core.llm.catalog as catalog_mod
    from mcp_core.auth.credential_form import _catalog_models_for_task

    # A synthetic registry larger than the old 100-slice, with a deepseek model
    # parked past index 100 — it must survive an un-capped catalog.
    big = [{"model": f"prov/model-{i:04d}", "provider": "prov", "mode": "chat"} for i in range(150)]
    big.append({"model": "azure_ai/deepseek-v3.2", "provider": "azure_ai", "mode": "chat"})

    captured: dict = {}

    def _fake_list_models(**kw):
        captured.update(kw)
        return big

    monkeypatch.setattr(catalog_mod, "list_models", _fake_list_models)
    result = _catalog_models_for_task("understand")
    # The limit passed must be high enough to cover the whole registry, not 100.
    assert captured["limit"] >= len(big)
    assert len(result) == len(big)
    assert "azure_ai/deepseek-v3.2" in result


# --- catalog: provider-API merge + bare-name normalization --------------------


def test_catalog_normalizes_bare_cohere_name(monkeypatch):
    """litellm returns bare 'embed-english-v3.0' (provider=cohere). The widget
    infers provider from the prefix, so a bare name would derive the WRONG key
    (openai). Normalize bare curated-provider ids to '<provider>/<name>'."""
    import mcp_core.llm.catalog as catalog_mod
    import mcp_core.llm.provider_catalog as pc
    from mcp_core.auth.credential_form import _catalog_models_for_task

    monkeypatch.setattr(pc, "provider_catalog_models", lambda task: [])
    monkeypatch.setattr(
        catalog_mod,
        "list_models",
        lambda **kw: [
            {"model": "embed-english-v3.0", "provider": "cohere", "mode": "embedding"},
            {"model": "cohere/embed-v4.0", "provider": "cohere", "mode": "embedding"},
            {"model": "azure_ai/Cohere-embed-v3", "provider": "azure_ai", "mode": "embedding"},
        ],
    )
    out = _catalog_models_for_task("embedding")
    assert "cohere/embed-english-v3.0" in out  # bare -> prefixed
    assert "cohere/embed-v4.0" in out  # already prefixed, unchanged
    assert "azure_ai/Cohere-embed-v3" in out  # already prefixed, untouched
    assert "embed-english-v3.0" not in out  # the bare form is gone


def test_catalog_merges_provider_api_models_first(monkeypatch):
    """Live provider-catalog (Jina) ids are merged in and listed before litellm."""
    import mcp_core.llm.catalog as catalog_mod
    import mcp_core.llm.provider_catalog as pc
    from mcp_core.auth.credential_form import _catalog_models_for_task

    monkeypatch.setattr(
        pc, "provider_catalog_models", lambda task: ["jina_ai/jina-embeddings-v5-text-small"]
    )
    monkeypatch.setattr(
        catalog_mod,
        "list_models",
        lambda **kw: [{"model": "openai/text-embedding-3-large", "provider": "openai", "mode": "embedding"}],
    )
    out = _catalog_models_for_task("embedding")
    assert out[0] == "jina_ai/jina-embeddings-v5-text-small"  # provider-API first
    assert "openai/text-embedding-3-large" in out
    # dedupe: a provider-API id also present in litellm appears once
    assert out.count("jina_ai/jina-embeddings-v5-text-small") == 1


def test_catalog_merge_graceful_when_provider_api_raises(monkeypatch):
    """provider_catalog failure must not break the litellm catalog path."""
    import mcp_core.llm.catalog as catalog_mod
    import mcp_core.llm.provider_catalog as pc
    from mcp_core.auth.credential_form import _catalog_models_for_task

    def _boom(task):
        raise RuntimeError("jina down")

    monkeypatch.setattr(pc, "provider_catalog_models", _boom)
    monkeypatch.setattr(
        catalog_mod,
        "list_models",
        lambda **kw: [{"model": "cohere/rerank-v3.5", "provider": "cohere", "mode": "rerank"}],
    )
    out = _catalog_models_for_task("rerank")
    assert out == ["cohere/rerank-v3.5"]
