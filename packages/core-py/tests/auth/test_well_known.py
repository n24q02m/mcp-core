"""Test OAuth well-known metadata generators."""

from unittest.mock import MagicMock

from mcp_core.auth.well_known import (
    authorization_server_metadata,
    derive_base_url,
    protected_resource_metadata,
)


def test_authorization_server_metadata():
    meta = authorization_server_metadata("http://127.0.0.1:9876")
    assert meta["issuer"] == "http://127.0.0.1:9876"
    assert meta["authorization_endpoint"] == "http://127.0.0.1:9876/authorize"
    assert meta["token_endpoint"] == "http://127.0.0.1:9876/token"
    assert "S256" in meta["code_challenge_methods_supported"]
    assert "authorization_code" in meta["grant_types_supported"]


def test_protected_resource_metadata():
    meta = protected_resource_metadata(
        resource="http://127.0.0.1:9876",
        authorization_servers=["http://127.0.0.1:9876"],
    )
    assert meta["resource"] == "http://127.0.0.1:9876"
    assert "http://127.0.0.1:9876" in meta["authorization_servers"]


def test_derive_base_url_from_env(monkeypatch):
    monkeypatch.setenv("PUBLIC_URL", "https://example.com/")
    request = MagicMock()
    request.base_url = "http://localhost:8000"

    assert derive_base_url(request) == "https://example.com"


def test_derive_base_url_from_request(monkeypatch):
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    request = MagicMock()
    request.base_url = "http://localhost:8000/"

    assert derive_base_url(request) == "http://localhost:8000"
