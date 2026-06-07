"""RSA JWT Issuer and JWKS generation helper."""

import datetime
import os
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

# Keys will be stored outside of the codebase to persist across server restarts
DEFAULT_KEYS_DIR = Path.home() / ".mcp-relay" / "jwt-keys"


class JWTIssuer:
    private_key: RSAPrivateKey
    public_key: RSAPublicKey

    def __init__(self, server_name: str, keys_dir: Path = DEFAULT_KEYS_DIR):
        self.server_name = server_name
        self.keys_dir = keys_dir
        self.private_key_path = self.keys_dir / f"{server_name}_private.pem"
        self.public_key_path = self.keys_dir / f"{server_name}_public.pem"

        self._kid = "key-1"
        self._load_or_generate_keys()

    def _load_or_generate_keys(self) -> None:
        self.keys_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        if os.name != "nt":
            self.keys_dir.chmod(0o700)

        if self.private_key_path.exists() and self.public_key_path.exists():
            with open(self.private_key_path, "rb") as f:
                loaded_private = serialization.load_pem_private_key(f.read(), password=None)
            if not isinstance(loaded_private, RSAPrivateKey):
                msg = f"Expected RSA private key at {self.private_key_path}, got {type(loaded_private).__name__}"
                raise TypeError(msg)
            self.private_key = loaded_private

            with open(self.public_key_path, "rb") as f:
                loaded_public = serialization.load_pem_public_key(f.read())
            if not isinstance(loaded_public, RSAPublicKey):
                msg = f"Expected RSA public key at {self.public_key_path}, got {type(loaded_public).__name__}"
                raise TypeError(msg)
            self.public_key = loaded_public
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            self.public_key = self.private_key.public_key()

            with open(self.private_key_path, "wb") as f:
                f.write(
                    self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )

            with open(self.public_key_path, "wb") as f:
                f.write(
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
            # Ensure proper file permissions
            self.private_key_path.chmod(0o600)
            self.public_key_path.chmod(0o644)

    def get_jwks(self) -> dict:
        """Return JWKS payload for /.well-known/jwks.json"""
        pn = self.public_key.public_numbers()

        def to_base64url(val: int) -> str:
            val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
            # Custom base64url without padding
            import base64

            return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("ascii")

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self._kid,
                    "n": to_base64url(pn.n),
                    "e": to_base64url(pn.e),
                }
            ]
        }

    def issue_access_token(self, sub: str, expires_in_seconds: int = 3600) -> str:
        """Issue an RS256 JWT access token (``typ="access"``)."""
        now = datetime.datetime.now(datetime.UTC)
        payload = {
            "iss": self.server_name,
            "aud": self.server_name,
            "sub": sub,
            "iat": now,
            "exp": now + datetime.timedelta(seconds=expires_in_seconds),
            "typ": "access",
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": self._kid})

    def issue_refresh_token(self, sub: str, expires_in_seconds: int = 2592000) -> str:
        """Issue an RS256 JWT refresh token (``typ="refresh"``).

        Defaults to a 30-day (2592000s) lifetime so long-running MCP clients
        can mint fresh access tokens without forcing the user back through the
        browser PKCE flow every hour. Same key / iss / aud as access tokens;
        the ``typ`` claim is the only thing that distinguishes them, and
        ``verify_access_token`` rejects ``typ="refresh"`` so a refresh token
        can never be used as an access token at the ``/mcp`` resource.
        """
        now = datetime.datetime.now(datetime.UTC)
        payload = {
            "iss": self.server_name,
            "aud": self.server_name,
            "sub": sub,
            "iat": now,
            "exp": now + datetime.timedelta(seconds=expires_in_seconds),
            "typ": "refresh",
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": self._kid})

    def verify_access_token(self, token: str) -> dict:
        """Verify a JWT access token and return its payload.

        Raises standard PyJWT exceptions on failure (bad signature, wrong
        issuer/audience, expired). Additionally rejects tokens whose ``typ``
        claim is ``"refresh"`` with ``jwt.InvalidTokenError`` so a refresh
        token cannot be replayed as an access token. Tokens with
        ``typ="access"`` OR a missing ``typ`` claim are accepted (the latter
        keeps already-issued pre-refresh-support tokens valid).
        """
        payload = jwt.decode(
            token,
            self.public_key,
            algorithms=["RS256"],
            audience=self.server_name,
            issuer=self.server_name,
        )
        if payload.get("typ") == "refresh":
            msg = "Refresh token cannot be used as an access token"
            raise jwt.InvalidTokenError(msg)
        return payload

    def verify_refresh_token(self, token: str) -> dict:
        """Verify a JWT refresh token and return its payload.

        Same key / audience / issuer checks as ``verify_access_token`` and
        raises the same standard PyJWT exceptions on failure. Additionally
        asserts ``typ=="refresh"`` (raising ``jwt.InvalidTokenError``
        otherwise) so an access token can never be exchanged at the refresh
        grant. ``jwt.InvalidTokenError`` is the base class for the library's
        decode errors, so existing ``except jwt.InvalidTokenError`` / ``except
        jwt.PyJWTError`` clauses already catch it.
        """
        payload = jwt.decode(
            token,
            self.public_key,
            algorithms=["RS256"],
            audience=self.server_name,
            issuer=self.server_name,
        )
        if payload.get("typ") != "refresh":
            msg = "Token is not a refresh token"
            raise jwt.InvalidTokenError(msg)
        return payload
