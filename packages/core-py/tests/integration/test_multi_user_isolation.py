"""Per-authorize sub uniqueness contract for local_oauth_app.

Two concurrent browser sessions hitting GET /authorize MUST receive distinct
sub UUIDs (mcp_core.auth.local_oauth_app:214) so that on_credentials_saved
sees unique SubjectContext per session, enabling consumer-side per-sub
credential storage in remote multi-user mode.

This test locks in the existing contract -- it does not introduce a new API.
"""

from __future__ import annotations

import re

import pytest
from starlette.testclient import TestClient

from mcp_core.auth.local_oauth_app import create_local_oauth_app

RELAY_SCHEMA = {
    "version": "1",
    "fields": [
        {"name": "API_KEY", "type": "string", "required": True, "label": "API Key"},
    ],
}


def _extract_nonce(html: str) -> str:
    m = re.search(r"nonce=([A-Za-z0-9_\-]+)", html)
    assert m, f"no nonce in form HTML: {html[:200]}"
    return m.group(1)


@pytest.mark.integration
def test_two_concurrent_authorize_sessions_get_distinct_subs() -> None:
    captured: list[dict[str, str]] = []

    def on_creds(_creds: dict[str, str], context: dict[str, str]) -> None:
        captured.append(dict(context))
        return None

    app, _issuer = create_local_oauth_app(
        server_name="test-server",
        relay_schema=RELAY_SCHEMA,
        on_credentials_saved=on_creds,
    )
    client = TestClient(app)

    pkce_params = {
        "client_id": "local-browser",
        "redirect_uri": "http://127.0.0.1:9999/cb",
        "state": "s",
        "code_challenge": "x" * 43,
        "code_challenge_method": "S256",
    }

    resp_a = client.get("/authorize", params=pkce_params)
    assert resp_a.status_code == 200
    nonce_a = _extract_nonce(resp_a.text)

    resp_b = client.get("/authorize", params=pkce_params)
    assert resp_b.status_code == 200
    nonce_b = _extract_nonce(resp_b.text)
    assert nonce_a != nonce_b, "concurrent authorize must produce distinct nonces"

    client.post(f"/authorize?nonce={nonce_a}", json={"API_KEY": "key_a"})
    client.post(f"/authorize?nonce={nonce_b}", json={"API_KEY": "key_b"})

    assert len(captured) == 2
    sub_a = captured[0]["sub"]
    sub_b = captured[1]["sub"]
    assert sub_a and sub_b
    assert sub_a != sub_b, "concurrent authorize must produce distinct subs"
