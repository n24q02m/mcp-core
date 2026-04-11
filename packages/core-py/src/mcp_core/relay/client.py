"""Relay client: passphrase generation, session creation, and polling."""

import asyncio
import base64
import json
import secrets
from dataclasses import dataclass
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from mcp_core.crypto.aes import decrypt
from mcp_core.crypto.ecdh import (
    derive_shared_secret,
    export_public_key,
    generate_key_pair,
    import_public_key,
)
from mcp_core.crypto.kdf import derive_aes_key
from mcp_core.relay.wordlist import WORDLIST
from mcp_core.schema.types import RelayConfigSchema


def generate_passphrase(word_count: int = 4) -> str:
    """Generate a Diceware passphrase using the EFF long wordlist.

    Uses rejection sampling for uniform distribution.

    Args:
        word_count: Number of words (default 4 = ~52 bits entropy).

    Returns:
        Hyphen-separated passphrase string.
    """
    words: list[str] = []
    max_val = (0x10000 // len(WORDLIST)) * len(WORDLIST)
    for _ in range(word_count):
        while True:
            index = secrets.randbelow(0x10000)
            if index < max_val:
                break
        words.append(WORDLIST[index % len(WORDLIST)])
    return "-".join(words)


@dataclass
class RelaySession:
    """Active relay session state."""

    session_id: str
    private_key: EllipticCurvePrivateKey
    public_key: EllipticCurvePublicKey
    passphrase: str
    relay_url: str


async def create_session(
    relay_base_url: str,
    server_name: str,
    schema: RelayConfigSchema,
) -> RelaySession:
    """Create a new relay session.

    Args:
        relay_base_url: Base URL of the relay server.
        server_name: Server identifier.
        schema: Relay config schema for the setup form.

    Returns:
        RelaySession with session ID, keys, passphrase, and relay URL.

    Raises:
        httpx.HTTPStatusError: If server returns non-2xx.
    """
    session_id = secrets.token_hex(32)
    private_key, public_key = generate_key_pair()
    passphrase = generate_passphrase()

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{relay_base_url}/api/sessions",
            json={
                "sessionId": session_id,
                "serverName": server_name,
                "schema": dict(schema),
            },
        )
        if response.status_code >= 400:
            msg = f"Relay session creation failed: {response.status_code}"
            raise RuntimeError(msg)

    pub_key_b64 = export_public_key(public_key)
    relay_url = f"{relay_base_url}/setup?s={session_id}#k={pub_key_b64}&p={quote(passphrase)}"

    return RelaySession(
        session_id=session_id,
        private_key=private_key,
        public_key=public_key,
        passphrase=passphrase,
        relay_url=relay_url,
    )


async def poll_for_result(
    relay_base_url: str,
    session: RelaySession,
    interval_s: float = 2.0,
    timeout_s: float = 600.0,
) -> dict[str, str]:
    """Poll the relay server for encrypted credentials.

    Args:
        relay_base_url: Base URL of the relay server.
        session: Active relay session.
        interval_s: Polling interval in seconds.
        timeout_s: Total timeout in seconds.

    Returns:
        Decrypted credentials dict.

    Raises:
        RuntimeError: On session expiry, unexpected status, or timeout.
    """
    import time

    deadline = time.monotonic() + timeout_s

    async with httpx.AsyncClient() as client:
        while time.monotonic() < deadline:
            response = await client.get(f"{relay_base_url}/api/sessions/{session.session_id}")

            if response.status_code == 200:
                body = response.json()

                if body.get("status") == "skipped":
                    # Cleanup session (best effort)
                    try:
                        await client.delete(f"{relay_base_url}/api/sessions/{session.session_id}")
                    except Exception:
                        pass
                    msg = "RELAY_SKIPPED"
                    raise RuntimeError(msg)

                result = body.get("result", body)
                browser_pub = import_public_key(result["browserPub"])
                shared_secret = derive_shared_secret(session.private_key, browser_pub)
                aes_key = derive_aes_key(shared_secret, session.passphrase)

                ciphertext = base64.b64decode(result["ciphertext"])
                iv = base64.b64decode(result["iv"])
                tag = base64.b64decode(result["tag"])

                plaintext = decrypt(aes_key, ciphertext, iv, tag)

                # Don't delete session — keep alive for bidirectional messaging.
                # Session auto-expires via TTL (10 min).

                return json.loads(plaintext)

            if response.status_code == 404:
                msg = "Session expired or not found"
                raise RuntimeError(msg)

            if response.status_code != 202:
                msg = f"Unexpected status: {response.status_code}"
                raise RuntimeError(msg)

            await asyncio.sleep(interval_s)

    msg = "Relay setup timed out"
    raise RuntimeError(msg)


async def send_message(
    relay_base_url: str,
    session_id: str,
    message: dict,
) -> str:
    """Push a message from server to browser via the relay.

    Args:
        relay_base_url: Base URL of the relay server.
        session_id: Active session ID.
        message: Dict with 'type', 'text', and optional 'data'.

    Returns:
        The generated message ID.

    Raises:
        RuntimeError: If the relay returns a non-2xx status.
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{relay_base_url}/api/sessions/{session_id}/messages",
            json=message,
        )
        if response.status_code >= 400:
            msg = f"Failed to send message: {response.status_code}"
            raise RuntimeError(msg)
        return response.json()["id"]


async def poll_for_responses(
    relay_base_url: str,
    session_id: str,
    message_id: str,
    interval_s: float = 2.0,
    timeout_s: float = 300.0,
) -> str:
    """Poll the relay for a browser response to a specific message.

    Args:
        relay_base_url: Base URL of the relay server.
        session_id: Active session ID.
        message_id: The message ID to wait for a response to.
        interval_s: Polling interval in seconds.
        timeout_s: Total timeout in seconds.

    Returns:
        The response value string.

    Raises:
        RuntimeError: On timeout or request failure.
    """
    import time

    deadline = time.monotonic() + timeout_s

    async with httpx.AsyncClient() as client:
        while time.monotonic() < deadline:
            response = await client.get(f"{relay_base_url}/api/sessions/{session_id}/responses")
            if response.status_code >= 400:
                msg = f"Failed to poll responses: {response.status_code}"
                raise RuntimeError(msg)

            body = response.json()
            for resp in body.get("responses", []):
                if resp.get("messageId") == message_id:
                    return resp["value"]

            await asyncio.sleep(interval_s)

    msg = "Timed out waiting for response"
    raise RuntimeError(msg)
