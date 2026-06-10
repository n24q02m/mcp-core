import base64
import hashlib
import secrets
from unittest.mock import patch
import re

from starlette.testclient import TestClient

from mcp_core.auth.local_oauth_app import create_local_oauth_app

RELAY_SCHEMA = {
    "server": "test-server",
    "displayName": "Test Server",
    "fields": [
        {"key": "API_KEY", "label": "API Key", "type": "password", "required": True},
    ],
}


def _pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier and code_challenge (S256)."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _extract_nonce(client: TestClient) -> str:
    """Helper to get a valid nonce for /authorize POST."""
    params = {
        "client_id": "test-client",
        "redirect_uri": "http://localhost/callback",
        "state": "test-state",
    }
    _, challenge = _pkce_pair()
    params.update({"code_challenge": challenge, "code_challenge_method": "S256"})
    resp = client.get("/authorize", params=params)
    match = re.search(r'nonce=([^"&]+)', resp.text)
    assert match is not None
    return match.group(1)


def test_authorize_post_mark_setup_complete_fails():
    """Verify that if _mark_config_setup_complete fails in authorize_post, it's caught.

    Covers: packages/core-py/src/mcp_core/auth/local_oauth_app.py:345 (approx)
    """
    app, _ = create_local_oauth_app(server_name="test-server", relay_schema=RELAY_SCHEMA)
    client = TestClient(app, base_url="http://localhost")
    nonce = _extract_nonce(client)

    # Patch the alias _mark_config_setup_complete inside the local_oauth_app module
    with patch("mcp_core.auth.local_oauth_app._mark_config_setup_complete") as mock_mark:
        mock_mark.side_effect = Exception("Storage error")
        resp = client.post(f"/authorize?nonce={nonce}", json={"API_KEY": "sk-test"})

        # Should still succeed because the exception is caught and logged
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        mock_mark.assert_called_once_with("test-server")


def test_otp_handler_mark_setup_complete_fails():
    """Verify that if _mark_config_setup_complete fails in otp_handler, it's caught.

    Covers: packages/core-py/src/mcp_core/auth/local_oauth_app.py:641 (approx)
    """

    def on_save(creds, _ctx):
        # Return an otp_required step to trigger the multi-step flow
        return {"type": "otp_required", "text": "Enter OTP", "field": "otp_code", "input_type": "text"}

    def on_step(data, _ctx):
        # Return None to indicate completion
        return None

    app, _ = create_local_oauth_app(
        server_name="test-server", relay_schema=RELAY_SCHEMA, on_credentials_saved=on_save, on_step_submitted=on_step
    )
    client = TestClient(app, base_url="http://localhost")
    nonce = _extract_nonce(client)

    # First POST to /authorize to trigger otp_required
    resp1 = client.post(f"/authorize?nonce={nonce}", json={"API_KEY": "sk-test"})
    assert resp1.status_code == 200
    assert resp1.json()["next_step"]["type"] == "otp_required"

    # Second POST to /otp to complete the flow.
    # TestClient maintains the session cookie from the first response.
    with patch("mcp_core.auth.local_oauth_app._mark_config_setup_complete") as mock_mark:
        mock_mark.side_effect = Exception("Storage error")
        resp2 = client.post("/otp", json={"otp_code": "123456"})

        # Should still succeed
        assert resp2.status_code == 200
        assert resp2.json()["ok"] is True
        mock_mark.assert_called_once_with("test-server")
