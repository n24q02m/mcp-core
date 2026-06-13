import pytest
from starlette.testclient import TestClient

from mcp_core.auth.local_oauth_app import create_local_oauth_app
from mcp_core.oauth.jwt_issuer import JWTIssuer


@pytest.fixture
def app_and_issuer(tmp_path):
    issuer = JWTIssuer(
        server_name="wet-mcp",
        keys_dir=tmp_path / "keys",
        credential_secret="test-credential-secret-value",
    )
    app, _ = create_local_oauth_app(
        server_name="wet-mcp",
        relay_schema={"fields": []},
        jwt_issuer=issuer,
    )
    return app, issuer


def test_jwks_endpoint_serves_okp_key(app_and_issuer):
    app, issuer = app_and_issuer
    client = TestClient(app)
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    body = resp.json()
    assert body == issuer.get_jwks()
    assert body["keys"][0]["kty"] == "OKP"
    assert body["keys"][0]["alg"] == "EdDSA"


def test_authorization_server_metadata_advertises_jwks_uri(app_and_issuer):
    app, _ = app_and_issuer
    client = TestClient(app)
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    meta = resp.json()
    assert meta["jwks_uri"].endswith("/.well-known/jwks.json")
