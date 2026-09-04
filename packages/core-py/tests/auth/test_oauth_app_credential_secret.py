"""OAuth-app fallback issuer secret selection.

``MCP_JWT_SIGNING_SECRET`` takes precedence so operators can revoke OAuth
tokens without rotating ``CREDENTIAL_SECRET`` (which also encrypts per-sub
vaults and derives stable subjects). Existing deployments retain the
``CREDENTIAL_SECRET`` fallback and cross-language signing-key parity.
"""

from __future__ import annotations

import jwt
import pytest
from mcp_core.auth.delegated_oauth_app import UpstreamOAuthConfig, create_delegated_oauth_app
from mcp_core.auth.local_oauth_app import create_local_oauth_app

_SECRET = "test-credential-secret-value"
_PARITY_KID = "r71l8IICMLZykZU5"


def test_local_factory_fallback_derives_eddsa_from_credential_secret(monkeypatch):
    monkeypatch.delenv("MCP_JWT_SIGNING_SECRET", raising=False)
    monkeypatch.setenv("CREDENTIAL_SECRET", _SECRET)
    _app, issuer = create_local_oauth_app(server_name="wet-mcp", relay_schema={"fields": []})
    assert issuer.alg == "EdDSA"
    assert issuer._kid == _PARITY_KID


def test_delegated_factory_fallback_derives_eddsa_from_credential_secret(monkeypatch):
    monkeypatch.delenv("MCP_JWT_SIGNING_SECRET", raising=False)
    monkeypatch.setenv("CREDENTIAL_SECRET", _SECRET)
    cfg = UpstreamOAuthConfig(
        token_url="https://example.test/token",
        client_id="upstream-client",
        scopes=["read"],
        authorize_url="https://example.test/authorize",
    )
    _app, issuer = create_delegated_oauth_app(
        server_name="wet-mcp",
        flow="redirect",
        upstream=cfg,
        on_token_received=lambda tokens: None,
    )
    assert issuer.alg == "EdDSA"
    assert issuer._kid == _PARITY_KID


def test_factories_prefer_domain_separated_jwt_signing_secret(monkeypatch):
    monkeypatch.setenv("CREDENTIAL_SECRET", _SECRET)
    monkeypatch.setenv("MCP_JWT_SIGNING_SECRET", "jwt-signing-secret-a")
    _local_app, old_issuer = create_local_oauth_app(server_name="wet-mcp", relay_schema={"fields": []})
    old_token = old_issuer.issue_access_token(sub="existing-sub")

    monkeypatch.setenv("MCP_JWT_SIGNING_SECRET", "jwt-signing-secret-b")
    cfg = UpstreamOAuthConfig(
        token_url="https://example.test/token",
        client_id="upstream-client",
        scopes=["read"],
        authorize_url="https://example.test/authorize",
    )
    _delegated_app, new_issuer = create_delegated_oauth_app(
        server_name="wet-mcp",
        flow="redirect",
        upstream=cfg,
        on_token_received=lambda tokens: None,
    )

    assert old_issuer._kid != new_issuer._kid
    with pytest.raises(jwt.InvalidSignatureError):
        new_issuer.verify_access_token(old_token)
