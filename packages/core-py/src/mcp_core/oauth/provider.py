"""OAuth 2.1 Provider logic for MCP servers.

This implements the "MCP Server as Authorization Server" pattern.
The MCP Server issues the JWTs, processes the PKCE verification,
and uses the Relay Server purely as a UI consent transport.
"""

import base64
import hashlib
import hmac
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from mcp_core.crypto.ecdh import export_private_key, import_private_key
from mcp_core.relay.client import RelaySession, create_session, poll_for_result

from .jwt_issuer import JWTIssuer


@dataclass
class PreAuthSession:
    """Pending auth before code exchange."""

    session_id: str
    client_id: str
    redirect_uri: str
    state: str
    code_challenge: str
    code_challenge_method: str
    private_key_b64: str
    passphrase: str
    expires_at: int


class IOAuthSessionCache(Protocol):
    """Cache for maintaining state between /authorize and /token endpoints."""

    def save(self, session: PreAuthSession) -> None: ...
    def get_and_delete(self, session_id: str) -> PreAuthSession | None: ...


class InMemoryAuthCache(IOAuthSessionCache):
    def __init__(self):
        self._cache: dict[str, PreAuthSession] = {}

    def save(self, session: PreAuthSession) -> None:
        self._cache[session.session_id] = session
        # Cleanup expired
        now = int(time.time())
        expired = [sid for sid, sess in self._cache.items() if sess.expires_at < now]
        for sid in expired:
            del self._cache[sid]

    def get_and_delete(self, session_id: str) -> PreAuthSession | None:
        if session_id in self._cache:
            sess = self._cache.pop(session_id)
            if sess.expires_at >= int(time.time()):
                return sess
        return None


class OAuthProvider:
    def __init__(
        self,
        server_name: str,
        relay_base_url: str,
        relay_schema: dict,
        jwt_issuer: JWTIssuer,
        cache: IOAuthSessionCache | None = None,
    ):
        self.server_name = server_name
        self.relay_base_url = relay_base_url
        self.relay_schema = relay_schema
        self.jwt_issuer = jwt_issuer
        self.cache = cache or InMemoryAuthCache()

    async def create_authorize_redirect(
        self,
        client_id: str,
        redirect_uri: str,
        state: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
    ) -> str:
        """Create a relay session and return the URL to redirect the user to."""

        # Call relay to create session, appending the oauthState param
        session = await create_session(
            self.relay_base_url,
            self.server_name,
            self.relay_schema,
            oauth_state={
                "clientId": client_id,
                "redirectUri": redirect_uri,
                "state": state,
                "codeChallenge": code_challenge,
                "codeChallengeMethod": code_challenge_method,
            },
        )

        # Store private key and passphrase temporarily
        pre_auth = PreAuthSession(
            session_id=session.session_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            private_key_b64=export_private_key(session.private_key),
            passphrase=session.passphrase,
            expires_at=int(time.time()) + 600,  # 10 mins
        )
        self.cache.save(pre_auth)
        return session.relay_url

    async def exchange_code(
        self,
        code: str,
        code_verifier: str,
        user_id_extractor: Callable[[dict], str],
    ) -> tuple[str, dict]:
        """
        Exchange the authorization code (which is the relay session_id)
        for an access_token. PKCE verification is performed.

        Args:
            code: The authorization code provided by the client.
            code_verifier: The PKCE code verifier.
            user_id_extractor: Function to derive a unique user_id from the credentials.

        Returns:
            Tuple of (access_token_jwt, credentials_dict)
        """
        pre_auth = self.cache.get_and_delete(code)
        if not pre_auth:
            raise ValueError("invalid_grant: Expired or invalid code")

        # Verify PKCE
        if pre_auth.code_challenge_method == "S256":
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            expected_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
            if not hmac.compare_digest(expected_challenge, pre_auth.code_challenge):
                raise ValueError("invalid_grant: PKCE verification failed")
        elif pre_auth.code_challenge_method == "plain":
            if not hmac.compare_digest(code_verifier, pre_auth.code_challenge):
                raise ValueError("invalid_grant: PKCE plain verification failed")
        else:
            raise ValueError("unsupported_challenge_method")

        # reconstruct RelaySession to decrypt
        relay_session = RelaySession(
            session_id=pre_auth.session_id,
            private_key=import_private_key(pre_auth.private_key_b64),
            public_key=None,  # Not needed for decryption
            passphrase=pre_auth.passphrase,
            relay_url="",
        )

        credentials = await poll_for_result(
            self.relay_base_url,
            relay_session,
            interval_s=1.0,
            timeout_s=10.0,
        )

        # Extract unique user_id
        user_id = user_id_extractor(credentials)
        if not user_id:
            raise ValueError("server_error: Unable to extract user_id from credentials")

        # Issue access token
        access_token = self.jwt_issuer.issue_access_token(sub=user_id)
        return access_token, credentials
