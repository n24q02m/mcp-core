import base64
import hashlib
import re
import secrets

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


def test_authorize_prefill_invalid_json():
    app, _ = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
    )
    client = TestClient(app, base_url="http://localhost")

    resp = client.post(
        "/authorize/prefill?state=state123",
        content="not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert "Body must be JSON object" in resp.json()["error_description"]


def test_otp_handler_invalid_json():
    def on_saved(creds, context):
        return {
            "type": "otp_required",
            "text": "Enter OTP",
            "field": "otp_code",
        }

    app, _ = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
        on_credentials_saved=on_saved,
    )
    client = TestClient(app, base_url="http://localhost")

    # 1. Start authorize to get a nonce
    _v, challenge = _pkce_pair()
    resp = client.get(
        f"/authorize?client_id=local-browser&response_type=code&"
        f"code_challenge={challenge}&code_challenge_method=S256&state=state123&"
        f"redirect_uri=http://localhost/callback"
    )
    match = re.search(r"nonce=([a-zA-Z0-9_-]+)", resp.text)
    nonce = match.group(1)

    # 2. POST authorize to trigger otp_required step
    resp = client.post(f"/authorize?nonce={nonce}", json={"API_KEY": "secret"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["next_step"]["type"] == "otp_required"

    # 3. POST /otp with invalid JSON
    resp = client.post(
        "/otp",
        content="not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert "Invalid JSON body" in resp.json()["error_description"]


def test_register_handler_invalid_json():
    app, _ = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
    )
    client = TestClient(app, base_url="http://localhost")

    resp = client.post(
        "/register",
        content="not json",
        headers={"Content-Type": "application/json"},
    )
    # register_handler handles exception by defaulting to empty dict
    assert resp.status_code == 201
    data = resp.json()
    assert data["client_id"] == "local-browser"
    assert data["client_name"] == "mcp-client"


def test_authorize_prefill_not_a_dict():
    app, _ = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
    )
    client = TestClient(app, base_url="http://localhost")

    resp = client.post(
        "/authorize/prefill?state=state123",
        json=[1, 2, 3],
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert "Body must be JSON object" in resp.json()["error_description"]


def test_register_handler_not_a_dict():
    app, _ = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
    )
    client = TestClient(app, base_url="http://localhost")

    resp = client.post(
        "/register",
        json="just a string",
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["client_id"] == "local-browser"
