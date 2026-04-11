"""Self-hosted OAuth 2.1 Authorization Server skeleton.

Handles /authorize (renders relay form HTML), /token (exchanges auth code for
JWT access token), and /.well-known/oauth-authorization-server.

For Notion delegated mode, see delegated.py.

Full implementation lands in a follow-up Phase I task. This stub establishes
the API surface so downstream packages can depend on it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class OAuthProvider:
    issuer: str
    jwt_private_key_pem: str
    jwt_public_key_pem: str

    async def handle_authorize(self, request: object) -> object:
        raise NotImplementedError("Implementation follows in a Phase I follow-up task")

    async def handle_token(self, request: object) -> object:
        raise NotImplementedError("Implementation follows in a Phase I follow-up task")

    async def handle_well_known(self, request: object) -> object:
        raise NotImplementedError("Implementation follows in a Phase I follow-up task")
