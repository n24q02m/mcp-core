"""Tests for local OAuth 2.1 Starlette app."""

import base64
import hashlib
import secrets

import pytest
from starlette.testclient import TestClient

from mcp_core.auth.local_oauth_app import create_local_oauth_app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

RELAY_SCHEMA = {
    "server": "test-server",
    "displayName": "Test Server",
    "description": "A test MCP server",
    "fields": [
        {
            "key": "API_KEY",
            "label": "API Key",
            "type": "password",
            "placeholder": "Enter your API key",
            "required": True,
        },
        {
            "key": "WORKSPACE",
            "label": "Workspace",
            "type": "text",
            "placeholder": "Optional workspace",
            "required": False,
        },
    ],
}


def _pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier and code_challenge (S256)."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@pytest.fixture()
def app_and_issuer():
    """Create app with default settings and a credential callback."""
    saved = {}

    def on_saved(creds: dict[str, str]) -> None:
        saved.update(creds)

    app, issuer = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
        on_credentials_saved=on_saved,
    )
    return app, issuer, saved


@pytest.fixture()
def client(app_and_issuer):
    app, _issuer, _saved = app_and_issuer
    return TestClient(app, base_url="http://localhost")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWellKnownMetadata:
    def test_authorization_server_metadata(self, client):
        """GET /.well-known/oauth-authorization-server returns valid RFC 8414 JSON."""
        resp = client.get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 200
        data = resp.json()
        assert data["issuer"] == "http://localhost"
        assert data["authorization_endpoint"] == "http://localhost/authorize"
        assert data["token_endpoint"] == "http://localhost/token"
        assert "code" in data["response_types_supported"]
        assert "authorization_code" in data["grant_types_supported"]
        assert "S256" in data["code_challenge_methods_supported"]
        assert "none" in data["token_endpoint_auth_methods_supported"]

    def test_protected_resource_metadata(self, client):
        """GET /.well-known/oauth-protected-resource returns correct RFC 9728 JSON."""
        resp = client.get("/.well-known/oauth-protected-resource")
        assert resp.status_code == 200
        data = resp.json()
        assert data["resource"] == "http://localhost"
        assert "http://localhost" in data["authorization_servers"]
        assert "header" in data["bearer_methods_supported"]


class TestAuthorizeEndpoint:
    def test_authorize_renders_form(self, client):
        """GET /authorize with valid PKCE params returns HTML with the credential form."""
        _verifier, challenge = _pkce_pair()
        resp = client.get(
            "/authorize",
            params={
                "client_id": "test-client",
                "redirect_uri": "http://localhost/callback",
                "state": "random-state",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        # Form should contain fields from relay_schema
        assert "API Key" in resp.text
        assert "Workspace" in resp.text

    def test_authorize_missing_params(self, client):
        """GET /authorize without required params returns 400."""
        resp = client.get("/authorize")
        assert resp.status_code == 400

    def test_authorize_saves_credentials(self, app_and_issuer):
        """POST /authorize with JSON credentials triggers on_credentials_saved callback."""
        app, _issuer, saved = app_and_issuer
        client = TestClient(app, base_url="http://localhost")

        verifier, challenge = _pkce_pair()

        # Step 1: GET /authorize to create the auth session
        resp = client.get(
            "/authorize",
            params={
                "client_id": "test-client",
                "redirect_uri": "http://localhost/callback",
                "state": "test-state",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert resp.status_code == 200

        # Extract nonce from the rendered form
        # The form's submit URL includes a nonce query param
        import re

        nonce_match = re.search(r'nonce=([^"&]+)', resp.text)
        assert nonce_match is not None, "Form should contain a nonce in the submit URL"
        nonce = nonce_match.group(1)

        # Step 2: POST /authorize with credentials + nonce
        resp = client.post(
            f"/authorize?nonce={nonce}",
            json={"API_KEY": "sk-test-123", "WORKSPACE": "my-workspace"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "redirect_url" in data

        # Verify credentials were saved
        assert saved["API_KEY"] == "sk-test-123"
        assert saved["WORKSPACE"] == "my-workspace"

    def test_authorize_post_invalid_nonce(self, client):
        """POST /authorize with invalid nonce returns 400."""
        resp = client.post(
            "/authorize?nonce=bogus-nonce",
            json={"API_KEY": "sk-test-123"},
        )
        assert resp.status_code == 400


class TestTokenExchange:
    def test_token_exchange_pkce(self, app_and_issuer):
        """Full PKCE flow: GET /authorize -> POST /authorize -> POST /token -> JWT."""
        app, issuer, _saved = app_and_issuer
        client = TestClient(app, base_url="http://localhost")

        verifier, challenge = _pkce_pair()
        redirect_uri = "http://localhost/callback"

        # Step 1: GET /authorize
        resp = client.get(
            "/authorize",
            params={
                "client_id": "test-client",
                "redirect_uri": redirect_uri,
                "state": "pkce-state",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert resp.status_code == 200

        import re

        nonce_match = re.search(r'nonce=([^"&]+)', resp.text)
        assert nonce_match is not None
        nonce = nonce_match.group(1)

        # Step 2: POST /authorize -> get auth code from redirect_url
        resp = client.post(
            f"/authorize?nonce={nonce}",
            json={"API_KEY": "sk-test-456"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

        # Parse the auth code from the redirect URL
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(data["redirect_url"])
        qs = parse_qs(parsed.query)
        assert "code" in qs
        assert qs["state"] == ["pkce-state"]
        auth_code = qs["code"][0]

        # Step 3: POST /token with auth_code + code_verifier
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "code_verifier": verifier,
                "redirect_uri": redirect_uri,
            },
        )
        assert resp.status_code == 200
        token_data = resp.json()
        assert "access_token" in token_data
        assert token_data["token_type"] == "Bearer"
        assert token_data["expires_in"] > 0

        # Verify the JWT is valid
        claims = issuer.verify_access_token(token_data["access_token"])
        assert claims["sub"] == "local-user"

    def test_token_invalid_code(self, client):
        """POST /token with a wrong/missing auth code returns 400."""
        verifier, _challenge = _pkce_pair()
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "invalid-code-xyz",
                "code_verifier": verifier,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    def test_token_invalid_verifier(self, app_and_issuer):
        """POST /token with wrong code_verifier fails PKCE check."""
        app, _issuer, _saved = app_and_issuer
        client = TestClient(app, base_url="http://localhost")

        verifier, challenge = _pkce_pair()

        # Create a valid auth code
        resp = client.get(
            "/authorize",
            params={
                "client_id": "test-client",
                "redirect_uri": "http://localhost/callback",
                "state": "s",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )

        import re

        nonce_match = re.search(r'nonce=([^"&]+)', resp.text)
        assert nonce_match is not None
        nonce = nonce_match.group(1)

        resp = client.post(
            f"/authorize?nonce={nonce}",
            json={"API_KEY": "key"},
        )
        data = resp.json()

        from urllib.parse import parse_qs, urlparse

        auth_code = parse_qs(urlparse(data["redirect_url"]).query)["code"][0]

        # Use WRONG verifier
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "code_verifier": "wrong-verifier-not-matching",
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    def test_token_unsupported_grant_type(self, client):
        """POST /token with unsupported grant_type returns 400."""
        resp = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "code": "abc",
                "code_verifier": "def",
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "unsupported_grant_type"

    def test_token_code_single_use(self, app_and_issuer):
        """Auth code can only be used once."""
        app, _issuer, _saved = app_and_issuer
        client = TestClient(app, base_url="http://localhost")

        verifier, challenge = _pkce_pair()

        resp = client.get(
            "/authorize",
            params={
                "client_id": "test-client",
                "redirect_uri": "http://localhost/callback",
                "state": "s",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )

        import re

        nonce_match = re.search(r'nonce=([^"&]+)', resp.text)
        assert nonce_match is not None
        nonce = nonce_match.group(1)

        resp = client.post(
            f"/authorize?nonce={nonce}",
            json={"API_KEY": "key"},
        )

        from urllib.parse import parse_qs, urlparse

        auth_code = parse_qs(urlparse(resp.json()["redirect_url"]).query)["code"][0]

        # First exchange: success
        resp1 = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "code_verifier": verifier,
            },
        )
        assert resp1.status_code == 200

        # Second exchange with same code: fail
        resp2 = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "code_verifier": verifier,
            },
        )
        assert resp2.status_code == 400
        assert resp2.json()["error"] == "invalid_grant"


class TestJWTIssuerReuse:
    def test_returns_provided_jwt_issuer(self):
        """When a JWTIssuer is provided, the same instance is returned."""
        from pathlib import Path

        from mcp_core.oauth.jwt_issuer import JWTIssuer

        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            issuer = JWTIssuer(server_name="test-server", keys_dir=Path(tmpdir))
            _app, returned_issuer = create_local_oauth_app(
                server_name="test-server",
                relay_schema=RELAY_SCHEMA,
                jwt_issuer=issuer,
            )
            assert returned_issuer is issuer

    def test_creates_jwt_issuer_when_none(self):
        """When no JWTIssuer is provided, one is created automatically."""
        _app, issuer = create_local_oauth_app(
            server_name="test-server",
            relay_schema=RELAY_SCHEMA,
        )
        from mcp_core.oauth.jwt_issuer import JWTIssuer

        assert isinstance(issuer, JWTIssuer)
