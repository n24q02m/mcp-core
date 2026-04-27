"""Drive the mcp-core local OAuth 2.1 AS to obtain a JWT for /mcp.

The driver acts as the OAuth client: it does PKCE, optionally DCR, calls the
``/authorize`` form, posts credentials, exchanges the auth code at ``/token``,
and returns the resulting access token.

Used by :mod:`e2e.client_runner` so the MCP Streamable HTTP transport can
reach ``/mcp`` with a valid Bearer token. Replaces the older
``relay_filler.fill_relay_form`` which only filled the form and never
collected the JWT.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qs, urlparse

import httpx

_FORM_ACTION_RE = re.compile(r'<form[^>]*action="([^"]+)"', re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r'<input[^>]*name="([^"]+)"', re.IGNORECASE)
# TS form is JS-driven: action is in a ``var submitUrl = "..."`` literal, not
# on the <form action="..."> attribute. Python form embeds <form action="...">.
# The driver tries the HTML attribute first, then falls back to the JS string.
_JS_SUBMIT_URL_RE = re.compile(r'submitUrl\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_LOCALHOST_REDIRECT = "http://localhost/callback"


def _pkce_pair() -> tuple[str, str]:
    """Return (verifier, S256 code_challenge) per RFC 7636."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


async def _register_client(client: httpx.AsyncClient, base_url: str) -> str:
    """Try Dynamic Client Registration; fall back to ``local-browser`` if the
    server doesn't expose ``/register`` (older mcp-core or local-relay-only).
    """
    try:
        r = await client.post(
            f"{base_url}/register",
            json={
                "redirect_uris": [_LOCALHOST_REDIRECT],
                "client_name": "e2e-driver",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
    except httpx.HTTPError:
        return "local-browser"
    if r.status_code in (200, 201):
        return str(r.json()["client_id"])
    return "local-browser"


async def acquire_jwt(
    base_url: str, creds: dict[str, str], timeout: float = 60.0
) -> str:
    """Drive the full PKCE + form-fill + token-exchange flow.

    Returns the JWT access token. Raises ``RuntimeError`` with the server's
    error body if the credential save fails or the token endpoint rejects
    the auth code.
    """
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        client_id = await _register_client(client, base_url)

        params = {
            "client_id": client_id,
            "redirect_uri": _LOCALHOST_REDIRECT,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
        }
        get_form = await client.get(f"{base_url}/authorize", params=params)
        get_form.raise_for_status()

        action_m = _FORM_ACTION_RE.search(get_form.text) or _JS_SUBMIT_URL_RE.search(
            get_form.text
        )
        if not action_m:
            raise RuntimeError(f"No form action in {base_url}/authorize")
        action = action_m.group(1)
        action_url = action if action.startswith("http") else f"{base_url}{action}"

        # Two form patterns:
        #  - Static <input name="..."> (Python core-py + Notion paste-token):
        #    the form HTML lists the exact field names the server expects, so
        #    the driver filters skret to that subset.
        #  - JS-rendered (email's multi-account form, mnemo-core OTP step):
        #    no <input> in the GET HTML — JS builds the payload at submit time.
        #    The driver falls back to posting the full skret namespace and
        #    relies on the server to ignore unknown fields.
        input_names = set(_INPUT_NAME_RE.findall(get_form.text))
        if input_names:
            payload = {k: v for k, v in creds.items() if k in input_names}
        else:
            payload = {k: v for k, v in creds.items() if k != "MCP_DCR_SERVER_SECRET"}
        if not payload:
            raise RuntimeError(
                f"No credentials to submit (form fields={sorted(input_names)})"
            )

        # TS local OAuth AS expects JSON body; Python AS accepts form-encoded.
        # Sending JSON works for both since Starlette's request.form() falls
        # back to JSON parsing on Content-Type: application/json.
        post = await client.post(action_url, json=payload)
        post.raise_for_status()
        body = post.json()
        if not body.get("ok"):
            raise RuntimeError(f"Credential save failed: {body}")

        redirect_url = body["redirect_url"]
        qs = parse_qs(urlparse(redirect_url).query)
        code = qs.get("code", [None])[0]
        if not code:
            raise RuntimeError(f"No auth code in redirect_url: {redirect_url}")

        token_resp = await client.post(
            f"{base_url}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _LOCALHOST_REDIRECT,
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )
        token_resp.raise_for_status()
        token_body = token_resp.json()
        access_token = token_body.get("access_token")
        if not access_token:
            raise RuntimeError(f"No access_token in /token response: {token_body}")
        return str(access_token)
