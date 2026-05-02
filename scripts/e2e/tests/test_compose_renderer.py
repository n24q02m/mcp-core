"""Tests for compose_renderer."""

from e2e.compose_renderer import render_compose


def test_render_notion_always_multi_user() -> None:
    """HTTP mode is always multi-user post-2026-05-02 — PUBLIC_URL +
    MCP_DCR_SERVER_SECRET always present, ``MCP_MODE`` env never set.
    """
    config = {
        "id": "notion-paste-token",
        "repo": "better-notion-mcp",
    }
    creds = {
        "NOTION_INTEGRATION_TOKEN": "secret_xxx",
        "MCP_DCR_SERVER_SECRET": "dcr_xxx",
    }
    out = render_compose(config, deployment="local", creds=creds, host_port=40123)

    assert "image: ghcr.io/n24q02m/better-notion-mcp" in out
    assert "127.0.0.1:40123:8080" in out
    assert "PUBLIC_URL" in out
    assert "MCP_DCR_SERVER_SECRET" in out
    assert "MCP_MODE" not in out, (
        "MCP_MODE was removed in spec 2026-05-01-stdio-pure-http-multiuser §5.2.3"
    )


def test_render_notion_oauth_includes_oauth_client_creds() -> None:
    config = {
        "id": "notion-oauth",
        "repo": "better-notion-mcp",
    }
    creds = {
        "NOTION_OAUTH_CLIENT_ID": "client_xxx",
        "NOTION_OAUTH_CLIENT_SECRET": "secret_xxx",
        "MCP_DCR_SERVER_SECRET": "dcr_xxx",
    }
    out = render_compose(config, deployment="remote", creds=creds, host_port=40123)

    assert "PUBLIC_URL" in out
    assert "MCP_DCR_SERVER_SECRET" in out
    assert "NOTION_OAUTH_CLIENT_ID" in out
    assert "client_xxx" in out


def test_render_wet_with_optional_keys() -> None:
    config = {
        "id": "wet-full",
        "repo": "wet-mcp",
    }
    creds = {
        "JINA_AI_API_KEY": "jina_k",
        "GEMINI_API_KEY": "gem_k",
    }
    out = render_compose(config, deployment="local", creds=creds, host_port=41000)
    assert "JINA_AI_API_KEY" in out
    assert "GEMINI_API_KEY" in out
    assert "OPENAI_API_KEY" not in out, "must not emit unset optional keys"


def test_render_unknown_repo_raises() -> None:
    import pytest

    config = {"id": "x", "repo": "unknown-mcp"}
    with pytest.raises(KeyError, match="unknown-mcp"):
        render_compose(config, deployment="local", creds={}, host_port=40000)
