import base64
import hashlib
import re
import secrets
from unittest.mock import patch

from starlette.testclient import TestClient

from mcp_core.auth.local_oauth_app import create_local_oauth_app

RELAY_SCHEMA = {
    "server": "test-server",
    "displayName": "Test Server",
    "fields": [{"key": "API_KEY", "type": "password", "required": True}],
}


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def test_on_credentials_saved_exception():
    def on_saved(creds, context):
        raise ValueError("Simulated failure")

    app, _ = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
        on_credentials_saved=on_saved,
    )
    client = TestClient(app, base_url="http://localhost")

    _v, challenge = _pkce_pair()
    resp = client.get(
        f"/authorize?client_id=local-browser&response_type=code&"
        f"code_challenge={challenge}&code_challenge_method=S256&state=state123&"
        f"redirect_uri=http://localhost/callback"
    )
    match = re.search(r"nonce=([a-zA-Z0-9_-]+)", resp.text)
    nonce = match.group(1)

    resp = client.post(f"/authorize?nonce={nonce}", json={"API_KEY": "secret"})
    assert resp.status_code == 500
    assert resp.json()["error"] == "server_error"


def test_on_credentials_saved_returns_error():
    def on_saved(creds, context):
        return {"type": "error", "text": "Callback-level error"}

    app, _ = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
        on_credentials_saved=on_saved,
    )
    client = TestClient(app, base_url="http://localhost")

    _v, challenge = _pkce_pair()
    resp = client.get(
        f"/authorize?client_id=local-browser&response_type=code&"
        f"code_challenge={challenge}&code_challenge_method=S256&state=state123&"
        f"redirect_uri=http://localhost/callback"
    )
    match = re.search(r"nonce=([a-zA-Z0-9_-]+)", resp.text)
    nonce = match.group(1)

    resp = client.post(f"/authorize?nonce={nonce}", json={"API_KEY": "secret"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is False
    assert resp.json()["error"] == "Callback-level error"


def test_authorize_post_invalid_json():
    app, _ = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
    )
    client = TestClient(app, base_url="http://localhost")

    _v, challenge = _pkce_pair()
    resp = client.get(
        f"/authorize?client_id=local-browser&response_type=code&"
        f"code_challenge={challenge}&code_challenge_method=S256&state=state123&"
        f"redirect_uri=http://localhost/callback"
    )
    match = re.search(r"nonce=([a-zA-Z0-9_-]+)", resp.text)
    nonce = match.group(1)

    resp = client.post(f"/authorize?nonce={nonce}", content="not json", headers={"Content-Type": "application/json"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert "Invalid JSON" in resp.json()["error_description"]


def test_mark_config_setup_complete_failure_authorize():
    # Test authorize_post failure branch
    # Mocking _mark_config_setup_complete in mcp_core.auth.local_oauth_app
    with patch("mcp_core.auth.local_oauth_app._mark_config_setup_complete", side_effect=Exception("simulated")):
        app, _ = create_local_oauth_app(
            server_name="test-server",
            relay_schema=RELAY_SCHEMA,
        )
        client = TestClient(app, base_url="http://localhost")

        _v, challenge = _pkce_pair()
        resp = client.get(
            f"/authorize?client_id=local-browser&response_type=code&"
            f"code_challenge={challenge}&code_challenge_method=S256&state=state123&"
            f"redirect_uri=http://localhost/callback"
        )
        match = re.search(r"nonce=([a-zA-Z0-9_-]+)", resp.text)
        nonce = match.group(1)

        # Should still succeed (returns redirect_url with code) because the exception is caught and logged
        resp = client.post(f"/authorize?nonce={nonce}", json={"API_KEY": "secret"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "code=" in data["redirect_url"]


def test_mark_config_setup_complete_failure_otp():
    # Test otp_handler failure branch
    def on_saved(creds, context):
        return {"type": "otp_required"}

    def on_step_submitted(data, context):
        return None  # Completion

    with patch("mcp_core.auth.local_oauth_app._mark_config_setup_complete", side_effect=Exception("simulated")):
        app, _ = create_local_oauth_app(
            server_name="test-server",
            relay_schema=RELAY_SCHEMA,
            on_credentials_saved=on_saved,
            on_step_submitted=on_step_submitted,
        )
        client = TestClient(app, base_url="http://localhost")

        _v, challenge = _pkce_pair()
        resp = client.get(
            f"/authorize?client_id=local-browser&response_type=code&"
            f"code_challenge={challenge}&code_challenge_method=S256&state=state123&"
            f"redirect_uri=http://localhost/callback"
        )
        match = re.search(r"nonce=([a-zA-Z0-9_-]+)", resp.text)
        nonce = match.group(1)

        # 1. Authorize -> returns otp_required
        resp = client.post(f"/authorize?nonce={nonce}", json={"API_KEY": "secret"})
        assert resp.status_code == 200
        assert resp.json()["next_step"]["type"] == "otp_required"

        # 2. OTP -> completes
        resp = client.post("/otp", json={"otp_code": "123456"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
