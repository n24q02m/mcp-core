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
