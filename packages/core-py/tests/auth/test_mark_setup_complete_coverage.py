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


def test_authorize_post_mark_setup_complete_failure():
    # Mocking _mark_config_setup_complete in the module where it's used
    with patch("mcp_core.auth.local_oauth_app._mark_config_setup_complete") as mock_mark:
        mock_mark.side_effect = Exception("Persistent storage failure")

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

        # This should call _mark_config_setup_complete, fail, log it, and continue
        resp = client.post(f"/authorize?nonce={nonce}", json={"API_KEY": "secret"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        # The code uses "redirect_url" in response_body: {"ok": True, "redirect_url": redirect_url}
        assert "code=" in resp.json()["redirect_url"]
        assert mock_mark.called


def test_otp_handler_mark_setup_complete_failure():
    # Multi-step flow
    RELAY_SCHEMA_MULTI = {
        "server": "test-server",
        "displayName": "Test Server",
        "fields": [{"key": "API_KEY", "type": "password", "required": True}],
    }

    def on_saved(creds, context):
        return {"type": "otp_required", "text": "Enter OTP"}

    def on_otp_submitted(otp, context):
        return None  # Success

    with patch("mcp_core.auth.local_oauth_app._mark_config_setup_complete") as mock_mark:
        mock_mark.side_effect = Exception("Persistent storage failure")

        app, _ = create_local_oauth_app(
            server_name="test-server",
            relay_schema=RELAY_SCHEMA_MULTI,
            on_credentials_saved=on_saved,
            on_step_submitted=on_otp_submitted,
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

        # 1. Post credentials -> returns next_step: otp_required
        resp = client.post(f"/authorize?nonce={nonce}", json={"API_KEY": "secret"})
        assert resp.status_code == 200
        assert resp.json()["next_step"]["type"] == "otp_required"
        assert not mock_mark.called  # Not called yet for multi-step

        # 2. Post OTP -> completion -> should call _mark_config_setup_complete
        resp = client.post(f"/otp?nonce={nonce}", json={"otp": "123456"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert mock_mark.called
