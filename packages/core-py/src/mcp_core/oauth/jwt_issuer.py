"""JWT Issuer and JWKS generation helper.

Two signing modes, selected at construction:

* LOCAL single-user (credential_secret unset): RSA-2048, RS256,
  kid="key-1", keys generated on first run and persisted to disk
  (keys_dir) so they survive restarts on a real machine. Behavior is
  byte-for-byte unchanged from the pre-stability-fix implementation.

* HTTP multi-user (credential_secret set): Ed25519, EdDSA, signing key
  DERIVED deterministically from CREDENTIAL_SECRET via HKDF-SHA256
  (derive_jwt_signing_seed). NO disk I/O. Every container replica converges
  on the same key without a shared volume or external secret store, so OAuth
  tokens survive container recreation (Watchtower :latest redeploys). The
  kid is the base64url SHA-256 thumbprint of the raw public key so a
  CREDENTIAL_SECRET change yields a distinguishable kid.

The two modes are different deployments that never exchange tokens (iss /
aud are server-scoped), so the per-mode algorithm split is permanent and
intentional, not a transition. Each process runs exactly one algorithm; the
verify accept-list is a single-element list, never a {RS256, EdDSA} union.
"""

import base64
import datetime
import hashlib
import logging
import os
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from mcp_core.crypto import derive_jwt_signing_seed

logger = logging.getLogger(__name__)

# Keys will be stored outside of the codebase to persist across server restarts
DEFAULT_KEYS_DIR = Path.home() / ".mcp-relay" / "jwt-keys"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class JWTIssuer:
    private_key: RSAPrivateKey | Ed25519PrivateKey
    public_key: RSAPublicKey | Ed25519PublicKey

    def __init__(
        self,
        server_name: str,
        keys_dir: Path = DEFAULT_KEYS_DIR,
        credential_secret: str | None = None,
    ):
        self.server_name = server_name
        self.keys_dir = keys_dir
        self.credential_secret = credential_secret
        self.private_key_path = self.keys_dir / f"{server_name}_private.pem"
        self.public_key_path = self.keys_dir / f"{server_name}_public.pem"

        if credential_secret:
            self.alg = "EdDSA"
            self._derive_eddsa_keys(credential_secret)
            # Don't name the source env var in the message: only server_name +
            # the public kid thumbprint are logged (never the secret), and the
            # literal "CREDENTIAL_SECRET" token trips the SAST logger-credential
            # heuristic for no real benefit.
            logger.info(
                "JWTIssuer[%s]: HTTP multi-user mode, EdDSA signing key derived (kid=%s)",
                server_name,
                self._kid,
            )
        else:
            self.alg = "RS256"
            self._kid = "key-1"
            self._load_or_generate_keys()
            logger.info(
                "JWTIssuer[%s]: local single-user mode, RS256 key on disk (%s)",
                server_name,
                self.keys_dir,
            )

    def _derive_eddsa_keys(self, credential_secret: str) -> None:
        seed = derive_jwt_signing_seed(credential_secret, self.server_name)
        self.private_key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self.private_key.public_key()
        raw_pub = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._kid = _b64url(hashlib.sha256(raw_pub).digest())[:16]

    def _load_or_generate_keys(self) -> None:
        self._ensure_keys_dir()
        if self.private_key_path.exists() and self.public_key_path.exists():
            self._load_keys()
        else:
            self._generate_keys()

    def _ensure_keys_dir(self) -> None:
        # mode=0o700 closes the TOCTOU window where a freshly-created keys dir
        # would briefly be world-readable before the chmod below; the chmod
        # still runs to fix an already-existing dir and to override umask.
        self.keys_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            self.keys_dir.chmod(0o700)

    def _load_keys(self) -> None:
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

    def _generate_keys(self) -> None:
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
        if os.name != "nt":
            self.private_key_path.chmod(0o600)
            self.public_key_path.chmod(0o644)

    def get_jwks(self) -> dict:
        """Return JWKS payload for /.well-known/jwks.json.

        Always emits a keys array. In RS256 mode the single entry is an RSA
        JWK; in EdDSA mode it is an OKP JWK. The array shape is the same so the
        endpoint and clients can stay multi-key-aware for future rotation
        (publish current + optionally retired public keys).
        """
        return {"keys": [self._public_jwk()]}

    def _public_jwk(self) -> dict:
        if self.alg == "EdDSA":
            assert isinstance(self.public_key, Ed25519PublicKey)
            raw_pub = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": self._kid,
                "x": _b64url(raw_pub),
            }

        assert isinstance(self.public_key, RSAPublicKey)
        pn = self.public_key.public_numbers()

        def to_base64url(val: int) -> str:
            val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
            return _b64url(val_bytes)

        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self._kid,
            "n": to_base64url(pn.n),
            "e": to_base64url(pn.e),
        }

    def issue_access_token(self, sub: str, expires_in_seconds: int = 3600) -> str:
        """Issue a JWT access token (typ="access") signed with the active alg."""
        now = datetime.datetime.now(datetime.UTC)
        payload = {
            "iss": self.server_name,
            "aud": self.server_name,
            "sub": sub,
            "iat": now,
            "exp": now + datetime.timedelta(seconds=expires_in_seconds),
            "typ": "access",
        }
        return jwt.encode(payload, self.private_key, algorithm=self.alg, headers={"kid": self._kid})

    def issue_refresh_token(self, sub: str, expires_in_seconds: int = 31536000) -> str:
        """Issue a JWT refresh token (typ="refresh") signed with the active alg.

        Defaults to a 1-year (31536000s) lifetime so long-running MCP clients
        can mint fresh access tokens without forcing the user back through the
        browser PKCE flow. The access token stays short-lived (1h); the refresh
        token is the renewal credential and is rotated on every use
        (_handle_refresh_token issues a new refresh token each time), so the
        security control is rotation, not a short TTL. A short refresh TTL was
        the residual re-auth driver: a self-hosted server a user touches only
        intermittently (less than once a month) would silently expire its
        refresh token between sessions, forcing a fresh browser OAuth tab on the
        next use. With a 1-year floor, only a genuinely long idle gap re-prompts.
        Same key / iss / aud as access tokens; the typ claim is the only
        thing that distinguishes them, and verify_access_token rejects
        typ="refresh" so a refresh token can never be used as an access token
        at the /mcp resource.
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
        return jwt.encode(payload, self.private_key, algorithm=self.alg, headers={"kid": self._kid})

    def verify_access_token(self, token: str) -> dict:
        """Verify a JWT access token and return its payload.

        Raises standard PyJWT exceptions on failure (bad signature, wrong
        issuer/audience, expired). The accept-list is the single active
        algorithm (self.alg), never a union. Additionally rejects tokens
        whose typ claim is "refresh" with jwt.InvalidTokenError so a
        refresh token cannot be replayed as an access token. Tokens with
        typ="access" OR a missing typ claim are accepted (the latter
        keeps already-issued pre-refresh-support tokens valid).
        """
        payload = jwt.decode(
            token,
            self.public_key,
            algorithms=[self.alg],
            audience=self.server_name,
            issuer=self.server_name,
        )
        if payload.get("typ") == "refresh":
            msg = "Refresh token cannot be used as an access token"
            raise jwt.InvalidTokenError(msg)
        return payload

    def verify_refresh_token(self, token: str) -> dict:
        """Verify a JWT refresh token and return its payload.

        Same key / audience / issuer checks as verify_access_token and
        raises the same standard PyJWT exceptions on failure. The accept-list is
        the single active algorithm (self.alg). Additionally asserts
        typ=="refresh" (raising jwt.InvalidTokenError otherwise) so an
        access token can never be exchanged at the refresh grant.
        jwt.InvalidTokenError is the base class for the library's decode
        errors, so existing except jwt.InvalidTokenError / except
        jwt.PyJWTError clauses already catch it.
        """
        payload = jwt.decode(
            token,
            self.public_key,
            algorithms=[self.alg],
            audience=self.server_name,
            issuer=self.server_name,
        )
        if payload.get("typ") != "refresh":
            msg = "Token is not a refresh token"
            raise jwt.InvalidTokenError(msg)
        return payload
