"""Factory-fallback parity with core-ts: when no ``JWTIssuer`` is injected,
``create_local_oauth_app`` / ``create_delegated_oauth_app`` must construct one
in EdDSA mode if ``CREDENTIAL_SECRET`` is set (HTTP multi-user), so the derived
stable signing key is used even when the consumer relies on the factory's own
fallback issuer. Without the env var the fallback keeps the RS256-on-disk local
path unchanged (covered by the issuer's own ``TestLocalRsaModeUnchanged``).

EdDSA mode derives the key from ``CREDENTIAL_SECRET`` and never touches disk, so
these tests write no PEM files. ``server_name="wet-mcp"`` + the canonical secret
reproduce the cross-language thumbprint kid from ``crypto-vectors.json``.
"""

from __future__ import annotations

from mcp_core.auth.delegated_oauth_app import UpstreamOAuthConfig, create_delegated_oauth_app
from mcp_core.auth.local_oauth_app import create_local_oauth_app

_SECRET = "test-credential-secret-value"
_PARITY_KID = "r71l8IICMLZykZU5"


def test_local_factory_fallback_derives_eddsa_from_credential_secret(monkeypatch):
    monkeypatch.setenv("CREDENTIAL_SECRET", _SECRET)
    _app, issuer = create_local_oauth_app(server_name="wet-mcp", relay_schema={"fields": []})
    assert issuer.alg == "EdDSA"
    assert issuer._kid == _PARITY_KID


def test_delegated_factory_fallback_derives_eddsa_from_credential_secret(monkeypatch):
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
