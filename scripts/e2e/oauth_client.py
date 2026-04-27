"""Drive the mcp-core local OAuth 2.1 AS to obtain a JWT for /mcp.

The driver acts as the OAuth client: it does PKCE, optionally DCR, calls the
``/authorize`` form, posts credentials, exchanges the auth code at ``/token``,
and returns the resulting access token.

Used by :mod:`e2e.client_runner` so the MCP Streamable HTTP transport can
reach ``/mcp`` with a valid Bearer token. Replaces the older
``relay_filler.fill_relay_form`` which only filled the form and never
collected the JWT.

Two flows are supported:

* :func:`acquire_jwt` — local-relay form fill (paste-token / API-keys form).
  The driver POSTs creds to ``/authorize``, gets ``{ok: true, redirect_url}``
  inline, parses the auth code, and exchanges it.
* :func:`acquire_jwt_via_upstream_consent` — delegated-OAuth flow (notion's
  ``MCP_MODE=remote-oauth``). The driver runs a local callback listener,
  passes its URL as ``redirect_uri``, hands the upstream consent URL back to
  the caller for the user-gate, and waits for the callback to land.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import secrets
from collections.abc import Awaitable, Callable
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
    base_url: str,
    creds: dict[str, str],
    timeout: float = 60.0,
    on_next_step: Callable[[dict], Awaitable[None]] | Callable[[dict], None] | None = None,
    poll_completion_url: str | None = None,
    poll_timeout: float = 600.0,
) -> str:
    """Drive the full PKCE + form-fill + token-exchange flow.

    Returns the JWT access token. Raises ``RuntimeError`` with the server's
    error body if the credential save fails or the token endpoint rejects
    the auth code.

    When the credential save returns ``next_step`` (e.g. email-outlook's
    ``oauth_device_code`` response containing ``verification_url`` +
    ``user_code``), ``on_next_step`` is invoked with that dict so the
    caller can announce the upstream URL to the user. The driver then
    polls ``poll_completion_url`` (typically ``{base}/setup-status``)
    until it reports ``complete`` before exchanging the auth code at
    ``/token``. The auth code itself is issued inline at /authorize but
    is only useful once the upstream device-code flow finishes — exchanging
    it earlier yields a JWT whose tools fail because Outlook isn't auth'd.
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

        # email-outlook returns ``next_step.type == "oauth_device_code"``
        # alongside the redirect_url. The browser displays the device-code
        # banner, the user signs in upstream, and the server's background
        # poller marks setup-status complete. We mirror that by announcing
        # the next_step and polling /setup-status until complete before
        # exchanging the code.
        next_step = body.get("next_step")
        if next_step:
            if on_next_step is not None:
                result = on_next_step(next_step)
                if asyncio.iscoroutine(result):
                    await result
            if poll_completion_url is None:
                raise RuntimeError(
                    f"Server returned next_step={next_step['type']} but no "
                    "poll_completion_url provided"
                )
            await _poll_until_complete(client, poll_completion_url, poll_timeout)

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


async def _poll_until_complete(
    client: httpx.AsyncClient, poll_url: str, timeout: float
) -> None:
    """Poll ``poll_url`` (typically ``/setup-status``) until ``state=complete``.

    Mirrors :func:`e2e.user_gate.announce_and_wait` but reuses the OAuth
    client's httpx session so we don't open a parallel connection. Raises
    ``TimeoutError`` if completion doesn't land in time, ``RuntimeError``
    on explicit error states reported by the server.
    """
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = await client.get(poll_url, timeout=5.0)
            if r.status_code == 200:
                data = r.json()
                state = data.get("state") or next(iter(data.values()), None)
                if state == "complete":
                    return
                if state == "error":
                    raise RuntimeError(f"Setup failed: {data}")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(3)
    raise TimeoutError(f"Setup-status not complete within {timeout}s ({poll_url})")


async def _start_callback_listener(
    code_future: asyncio.Future[tuple[str, str]],
) -> tuple[asyncio.AbstractServer, int]:
    """Bind 127.0.0.1:<random> and resolve ``code_future`` on first GET.

    Returns the started server and the port it listened on. The handler
    accepts any path, parses ``code`` + ``state`` from the query string,
    and replies with a small HTML page so the user's browser shows
    something other than ``Connection refused``.
    """

    async def handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request_line = await reader.readline()
            try:
                _method, path, _proto = request_line.decode("ascii").split(" ", 2)
            except ValueError:
                writer.close()
                return

            # Drain headers — ignore content; OAuth callback is GET-only.
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"", b"\n"):
                    break

            qs = parse_qs(urlparse(path).query)
            code = qs.get("code", [""])[0]
            state = qs.get("state", [""])[0]
            if code and not code_future.done():
                code_future.set_result((code, state))

            body = (
                b"<!doctype html><html><body>"
                b"<h2>OAuth callback received</h2>"
                b"<p>You can close this tab and return to the terminal.</p>"
                b"</body></html>"
            )
            writer.write(b"HTTP/1.1 200 OK\r\n")
            writer.write(b"Content-Type: text/html; charset=utf-8\r\n")
            writer.write(f"Content-Length: {len(body)}\r\n".encode("ascii"))
            writer.write(b"Connection: close\r\n\r\n")
            writer.write(body)
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handler, host="127.0.0.1", port=0)
    sock = server.sockets[0]
    port = sock.getsockname()[1]
    return server, port


async def acquire_jwt_via_upstream_consent(
    base_url: str,
    announce: Callable[[str], Awaitable[None]] | Callable[[str], None],
    timeout: float = 600.0,
) -> str:
    """Drive a delegated-OAuth flow that requires upstream user consent.

    Notion remote-oauth, Microsoft device-code (when surfaced as a redirect
    flow), and any future provider that hands the browser off to a third
    party fit this shape. The local mcp server's ``/authorize`` returns
    ``302 Location: <upstream consent URL>`` with the upstream's
    ``redirect_uri`` set to its own ``/callback``. After consent, the local
    server exchanges with the upstream, then redirects the browser to OUR
    ``redirect_uri`` (the listener bound by this function) with a fresh
    auth code we can swap for a JWT at ``/token``.

    ``announce`` receives the upstream consent URL and is expected to
    surface it to the user (e.g. via :func:`e2e.user_gate.announce_and_wait`
    or a plain ``print``). It may be a sync or async callable.
    """
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)

    code_future: asyncio.Future[tuple[str, str]] = (
        asyncio.get_event_loop().create_future()
    )
    server, port = await _start_callback_listener(code_future)
    try:
        redirect_uri = f"http://127.0.0.1:{port}/callback"

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            client_id = await _register_client(client, base_url)
            params = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "response_type": "code",
            }
            resp = await client.get(f"{base_url}/authorize", params=params)
            if resp.status_code not in (302, 303, 307):
                raise RuntimeError(
                    f"Expected /authorize 302 to upstream, got "
                    f"{resp.status_code}: {resp.text[:200]}"
                )
            upstream_url = resp.headers.get("Location")
            if not upstream_url:
                raise RuntimeError("/authorize 302 missing Location header")

            result = announce(upstream_url)
            if asyncio.iscoroutine(result):
                await result

            try:
                code, returned_state = await asyncio.wait_for(
                    code_future, timeout=timeout
                )
            except asyncio.TimeoutError as e:
                raise TimeoutError(
                    f"OAuth callback not received within {timeout}s — "
                    f"user consent not completed"
                ) from e
            if returned_state != state:
                raise RuntimeError(
                    f"OAuth state mismatch: expected {state}, got {returned_state}"
                )

            token_resp = await client.post(
                f"{base_url}/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
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
    finally:
        server.close()
        await server.wait_closed()
