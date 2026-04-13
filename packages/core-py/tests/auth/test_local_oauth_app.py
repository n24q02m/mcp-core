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

        nonce = re.search(r'nonce=([^"&]+)', resp.text).group(1)

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

        nonce = re.search(r'nonce=([^"&]+)', resp.text).group(1)

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


# ---------------------------------------------------------------------------
# Multi-step auth fixtures and helpers (OTP / 2FA password)
# ---------------------------------------------------------------------------


def _authorize_params() -> dict[str, str]:
    """Standard PKCE authorize query params for multi-step auth tests."""
    _verifier, challenge = _pkce_pair()
    return {
        "client_id": "test-client",
        "redirect_uri": "http://localhost/callback",
        "state": "otp-state",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }


def _extract_nonce(client: TestClient) -> str:
    """Extract nonce from the form action URL in the last GET /authorize response.

    Issues a fresh GET /authorize with standard params to capture the nonce.
    """
    import re

    resp = client.get("/authorize", params=_authorize_params())
    match = re.search(r'nonce=([^"&]+)', resp.text)
    assert match is not None, "Form should contain a nonce"
    return match.group(1)


@pytest.fixture()
def client_with_otp():
    """TestClient where credential submit returns otp_required, and step completes (None)."""
    saved: dict[str, str] = {}

    def on_saved(creds: dict[str, str]) -> dict:
        saved.update(creds)
        return {"type": "otp_required", "prompt": "Enter the code sent to your phone"}

    def on_step(step: dict[str, str]) -> None:
        # Completion: accept any code, return None
        saved.update(step)
        return None

    app, _issuer = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
        on_credentials_saved=on_saved,
        on_step_submitted=on_step,
    )
    return TestClient(app, base_url="http://localhost"), saved


@pytest.fixture()
def client_with_2fa():
    """TestClient where flow is creds -> otp_required -> password_required -> complete."""
    saved: dict[str, str] = {}
    state = {"step": 0}

    def on_saved(creds: dict[str, str]) -> dict:
        saved.update(creds)
        return {"type": "otp_required", "prompt": "Enter OTP"}

    def on_step(step: dict[str, str]) -> dict | None:
        saved.update(step)
        state["step"] += 1
        if state["step"] == 1:
            # After OTP, require 2FA password
            return {"type": "password_required", "prompt": "Enter 2FA password"}
        # Second step: complete
        return None

    app, _issuer = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
        on_credentials_saved=on_saved,
        on_step_submitted=on_step,
    )
    return TestClient(app, base_url="http://localhost"), saved


@pytest.fixture()
def client_with_otp_error():
    """TestClient where on_step returns error dict, allowing retry."""
    saved: dict[str, str] = {}

    def on_saved(creds: dict[str, str]) -> dict:
        saved.update(creds)
        return {"type": "otp_required", "prompt": "Enter OTP"}

    def on_step(_step: dict[str, str]) -> dict:
        return {"type": "error", "text": "Invalid OTP code"}

    app, _issuer = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
        on_credentials_saved=on_saved,
        on_step_submitted=on_step,
    )
    return TestClient(app, base_url="http://localhost"), saved


# ---------------------------------------------------------------------------
# /otp endpoint tests (Phase L Track 1: multi-step auth)
# ---------------------------------------------------------------------------


def test_otp_endpoint_completes_setup(client_with_otp):
    """POST /otp with valid step data should complete setup."""
    client, _saved = client_with_otp
    nonce = _extract_nonce(client)
    resp = client.post(f"/authorize?nonce={nonce}", json={"TELEGRAM_PHONE": "+1234567890"})
    data = resp.json()
    assert data["ok"] is True
    assert data["next_step"]["type"] == "otp_required"
    resp = client.post("/otp", json={"otp_code": "12345"})
    data = resp.json()
    assert data["ok"] is True
    assert "next_step" not in data


def test_otp_endpoint_chains_to_password(client_with_2fa):
    """POST /otp should chain to password_required when callback says so."""
    client, _ = client_with_2fa
    nonce = _extract_nonce(client)
    client.post(f"/authorize?nonce={nonce}", json={"TELEGRAM_PHONE": "+1234567890"})
    resp = client.post("/otp", json={"otp_code": "12345"})
    data = resp.json()
    assert data["ok"] is True
    assert data["next_step"]["type"] == "password_required"
    resp = client.post("/otp", json={"password": "secret"})
    data = resp.json()
    assert data["ok"] is True
    assert "next_step" not in data


def test_otp_endpoint_returns_error_on_callback_error(client_with_otp_error):
    """POST /otp should return error when callback returns error, allow retry."""
    client, _ = client_with_otp_error
    nonce = _extract_nonce(client)
    client.post(f"/authorize?nonce={nonce}", json={"TELEGRAM_PHONE": "+1234567890"})
    resp = client.post("/otp", json={"otp_code": "wrong"})
    data = resp.json()
    assert data["ok"] is False
    assert "Invalid" in data["error"]


def test_otp_endpoint_without_prior_authorize_returns_400(client_with_otp):
    """POST /otp without prior credential submission should fail with 400."""
    client, _ = client_with_otp
    resp = client.post("/otp", json={"otp_code": "12345"})
    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "invalid_request"
    assert "no active" in data["error_description"].lower()


def test_otp_endpoint_timeout_clears_session(client_with_otp, monkeypatch):
    """After 300s, /otp session should expire and be cleared."""
    import time

    from mcp_core.auth import local_oauth_app

    client, _ = client_with_otp
    nonce = _extract_nonce(client)
    client.post(f"/authorize?nonce={nonce}", json={"TELEGRAM_PHONE": "+1234567890"})

    # Monkey-patch monotonic clock to simulate 301s elapsed
    original = time.monotonic
    base = original()
    monkeypatch.setattr(local_oauth_app.time, "monotonic", lambda: base + 301)

    resp = client.post("/otp", json={"otp_code": "12345"})
    assert resp.status_code == 400
    data = resp.json()
    assert data["error"] == "invalid_request"
    assert "expired" in data["error_description"].lower()

    # Subsequent calls should see "No active step session"
    monkeypatch.setattr(local_oauth_app.time, "monotonic", lambda: base + 302)
    resp = client.post("/otp", json={"otp_code": "12345"})
    assert resp.status_code == 400
    assert "no active" in resp.json()["error_description"].lower()


def test_otp_endpoint_max_attempts_clears_session(client_with_otp_error):
    """After 5 attempts with error, 6th should return 'Too many attempts' and clear."""
    client, _ = client_with_otp_error
    nonce = _extract_nonce(client)
    client.post(f"/authorize?nonce={nonce}", json={"TELEGRAM_PHONE": "+1234567890"})

    # 5 allowed attempts, all returning error
    for _ in range(5):
        resp = client.post("/otp", json={"otp_code": "wrong"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is False

    # 6th attempt: over limit, should be rejected with 400
    resp = client.post("/otp", json={"otp_code": "wrong"})
    assert resp.status_code == 400
    assert "too many" in resp.json()["error_description"].lower()

    # Subsequent calls see "No active session"
    resp = client.post("/otp", json={"otp_code": "wrong"})
    assert resp.status_code == 400
    assert "no active" in resp.json()["error_description"].lower()


# ---------------------------------------------------------------------------
# Async callback tests (regression: running-loop bug in telegram)
# ---------------------------------------------------------------------------


@pytest.fixture()
def client_with_async_otp():
    """Test fixture where callbacks are async. The handler must await them."""

    async def on_save(creds: dict[str, str]) -> dict:
        return {
            "type": "otp_required",
            "text": "Enter OTP",
            "field": "otp_code",
            "input_type": "text",
        }

    async def on_step(_data: dict[str, str]) -> None:
        return None  # complete

    app, _issuer = create_local_oauth_app(
        server_name="test",
        relay_schema={
            "server": "test",
            "displayName": "Test",
            "fields": [
                {
                    "key": "TELEGRAM_PHONE",
                    "label": "Phone",
                    "type": "tel",
                    "required": True,
                }
            ],
        },
        on_credentials_saved=on_save,
        on_step_submitted=on_step,
    )
    return TestClient(app, base_url="http://localhost"), {}


def test_otp_endpoint_with_async_callbacks(client_with_async_otp):
    """Async callbacks should be awaited properly -- no running-loop error."""
    client, _ = client_with_async_otp
    nonce = _extract_nonce(client)
    resp = client.post(f"/authorize?nonce={nonce}", json={"TELEGRAM_PHONE": "+1234567890"})
    data = resp.json()
    assert data["ok"] is True
    assert data["next_step"]["type"] == "otp_required"

    resp = client.post("/otp", json={"otp_code": "12345"})
    data = resp.json()
    assert data["ok"] is True
    assert "next_step" not in data


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


# ---------------------------------------------------------------------------
# Custom credential form HTML hook
# ---------------------------------------------------------------------------


def test_authorize_uses_custom_html_when_provided():
    """GET /authorize should render custom HTML when custom_credential_form_html is set."""

    def custom_renderer(schema, submit_url):
        return f"<!DOCTYPE html><html><body><h1>Custom</h1><form action='{submit_url}'></form></body></html>"

    app, _ = create_local_oauth_app(
        server_name="test",
        relay_schema={"server": "test", "displayName": "Test", "fields": []},
        custom_credential_form_html=custom_renderer,
    )
    client = TestClient(app)
    resp = client.get("/authorize", params=_authorize_params())
    assert resp.status_code == 200
    assert "<h1>Custom</h1>" in resp.text
    # Custom HTML should NOT contain the default form's title.
    assert "Enter your credentials" not in resp.text
    # But nonce must still be in submit_url.
    assert "nonce=" in resp.text


def test_authorize_uses_default_html_when_custom_not_provided():
    """GET /authorize should use default renderer when custom_credential_form_html not set."""
    app, _ = create_local_oauth_app(
        server_name="test",
        relay_schema={"server": "test", "displayName": "Test", "fields": []},
    )
    client = TestClient(app)
    resp = client.get("/authorize", params=_authorize_params())
    assert resp.status_code == 200
    # Default renderer emits this text.
    assert "Enter your credentials" in resp.text


def test_custom_renderer_receives_schema_and_submit_url():
    """custom_credential_form_html should be called with (relay_schema, submit_url)."""
    captured: dict = {}
    schema = {
        "server": "test",
        "displayName": "Test",
        "fields": [{"key": "X", "label": "X", "type": "text", "required": True}],
    }

    def custom_renderer(s, submit_url):
        captured["schema"] = s
        captured["submit_url"] = submit_url
        return "<html></html>"

    app, _ = create_local_oauth_app(
        server_name="test",
        relay_schema=schema,
        custom_credential_form_html=custom_renderer,
    )
    client = TestClient(app)
    resp = client.get("/authorize", params=_authorize_params())
    assert resp.status_code == 200
    # Schema passed through identically.
    assert captured["schema"] == schema
    # Submit URL must contain the nonce query string.
    assert "/authorize?nonce=" in captured["submit_url"]
