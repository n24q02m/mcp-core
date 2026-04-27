"""RSA JWT Issuer and JWKS generation helper."""

import datetime
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
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        import os
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
        """Issue an RS256 JWT access token."""
        now = datetime.datetime.now(datetime.UTC)
        payload = {
            "iss": self.server_name,
            "aud": self.server_name,
            "sub": sub,
            "iat": now,
            "exp": now + datetime.timedelta(seconds=expires_in_seconds),
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": self._kid})

    def verify_access_token(self, token: str) -> dict:
        """Verify JWT and return payload. Raises standard PyJWT exceptions on failure."""
        return jwt.decode(
            token,
            self.public_key,
            algorithms=["RS256"],
            audience=self.server_name,
            issuer=self.server_name,
        )
