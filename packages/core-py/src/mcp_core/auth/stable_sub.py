"""Derive a stable, opaque subject id from a workspace username.

Same ``(server_name, normalized username)`` -> same ``sub``, so a returning user
lands on the same per-``sub`` credential/data bucket (instead of the random
``secrets.token_urlsafe(16)`` minted per ``/authorize``). Keyed by
``CREDENTIAL_SECRET`` so the sub is unpredictable from outside.

SECURITY: with a SHARED relay password the username is a PARTITION key, NOT a
secret -- anyone who knows the password can submit any username and reach that
bucket. Intentional for a trusted group; untrusted multi-tenant needs per-user
secrets or delegated OAuth.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

# Used only when CREDENTIAL_SECRET is unset (single-user/dev): the sub stays
# stable, just predictable. Production multi-user always sets CREDENTIAL_SECRET.
_DEV_FALLBACK_KEY = b"mcp-core-stable-sub-dev-salt"


def derive_stable_sub(username: str, server_name: str, credential_secret: str | None) -> str:
    """Return an opaque, urlsafe-base64 subject id stable for this username.

    The output shape (~22 chars, no padding) matches ``secrets.token_urlsafe(16)``
    so downstream code cannot tell a stable sub from a random one.
    """
    normalized = username.strip().casefold()
    if not normalized:
        raise ValueError("username must be non-empty")
    key = credential_secret.encode() if credential_secret else _DEV_FALLBACK_KEY
    msg = f"sub:{server_name}:{normalized}".encode()
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()
