import os
import stat

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_core.oauth.jwt_issuer import JWTIssuer


@pytest.fixture
def keys_dir(tmp_path):
    return tmp_path / "keys"


@pytest.fixture
def issuer(keys_dir):
    return JWTIssuer(server_name="test-server", keys_dir=keys_dir)


class TestKeyGeneration:
    def test_generates_keys_if_not_exist(self, keys_dir):
        server_name = "new-server"
        private_path = keys_dir / f"{server_name}_private.pem"
        public_path = keys_dir / f"{server_name}_public.pem"

        assert not private_path.exists()
        assert not public_path.exists()

        JWTIssuer(server_name=server_name, keys_dir=keys_dir)

        assert private_path.exists()
        assert public_path.exists()

        # Check permissions (POSIX only)
        if os.name == "posix":
            assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
            assert stat.S_IMODE(public_path.stat().st_mode) == 0o644

    def test_generated_keys_are_valid_rsa(self, issuer):
        assert isinstance(issuer.private_key, rsa.RSAPrivateKey)
        assert isinstance(issuer.public_key, rsa.RSAPublicKey)
        assert issuer.private_key.key_size == 2048


class TestKeyPersistence:
    def test_loads_existing_keys(self, keys_dir):
        server_name = "persistent-server"

        # 1. Generate keys first
        issuer1 = JWTIssuer(server_name=server_name, keys_dir=keys_dir)
        priv1 = issuer1.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # 2. Load again
        issuer2 = JWTIssuer(server_name=server_name, keys_dir=keys_dir)
        priv2 = issuer2.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        assert priv1 == priv2

    def test_raises_type_error_on_invalid_private_key_type(self, keys_dir):
        server_name = "invalid-priv-key"
        keys_dir.mkdir(parents=True, exist_ok=True)

        # Write a public key where a private key is expected
        from cryptography.hazmat.primitives.asymmetric import ec

        invalid_key = ec.generate_private_key(ec.SECP256R1())

        with open(keys_dir / f"{server_name}_private.pem", "wb") as f:
            f.write(
                invalid_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # We also need a public key file to trigger the load path
        with open(keys_dir / f"{server_name}_public.pem", "wb") as f:
            f.write(b"garbage")

        with pytest.raises(TypeError, match="Expected RSA private key"):
            JWTIssuer(server_name=server_name, keys_dir=keys_dir)

    def test_raises_type_error_on_invalid_public_key_type(self, keys_dir):
        server_name = "invalid-pub-key"
        keys_dir.mkdir(parents=True, exist_ok=True)

        # Generate valid private key
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(keys_dir / f"{server_name}_private.pem", "wb") as f:
            f.write(
                priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Write an EC public key where RSA public key is expected
        from cryptography.hazmat.primitives.asymmetric import ec

        invalid_pub = ec.generate_private_key(ec.SECP256R1()).public_key()

        with open(keys_dir / f"{server_name}_public.pem", "wb") as f:
            f.write(
                invalid_pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

        with pytest.raises(TypeError, match="Expected RSA public key"):
            JWTIssuer(server_name=server_name, keys_dir=keys_dir)


class TestJWKS:
    def test_get_jwks_format(self, issuer):
        jwks = issuer.get_jwks()
        assert "keys" in jwks
        assert len(jwks["keys"]) == 1
        key = jwks["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"
        assert "n" in key
        assert "e" in key
        assert key["kid"] == "key-1"


class TestTokenOperations:
    def test_issue_and_verify_roundtrip(self, issuer):
        sub = "user-123"
        token = issuer.issue_access_token(sub=sub)

        payload = issuer.verify_access_token(token)
        assert payload["sub"] == sub
        assert payload["iss"] == "test-server"
        assert payload["aud"] == "test-server"
        assert payload["typ"] == "access"
        assert "iat" in payload
        assert "exp" in payload

    def test_verify_fails_with_wrong_issuer(self, keys_dir):
        issuer1 = JWTIssuer(server_name="issuer-1", keys_dir=keys_dir)
        # issuer2 uses same keys as issuer1 but different server_name
        issuer2 = JWTIssuer(server_name="issuer-2", keys_dir=keys_dir)
        # Force same keys
        issuer2.public_key = issuer1.public_key

        token = issuer1.issue_access_token(sub="user")

        with pytest.raises(jwt.InvalidIssuerError):
            issuer2.verify_access_token(token)

    def test_verify_fails_with_expired_token(self, issuer):
        token = issuer.issue_access_token(sub="user", expires_in_seconds=-10)

        with pytest.raises(jwt.ExpiredSignatureError):
            issuer.verify_access_token(token)

    def test_verify_fails_with_tampered_token(self, issuer):
        token = issuer.issue_access_token(sub="user")
        parts = token.split(".")
        # Change something in the payload
        import base64
        import json

        payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
        payload = json.loads(payload_bytes)
        payload["sub"] = "hacker"
        parts[1] = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        tampered_token = ".".join(parts)

        with pytest.raises(jwt.InvalidSignatureError):
            issuer.verify_access_token(tampered_token)


class TestRefreshTokenOperations:
    """Refresh token issuance + verification (issue #261)."""

    def test_issue_and_verify_refresh_roundtrip(self, issuer):
        sub = "user-456"
        token = issuer.issue_refresh_token(sub=sub)

        payload = issuer.verify_refresh_token(token)
        assert payload["sub"] == sub
        assert payload["iss"] == "test-server"
        assert payload["aud"] == "test-server"
        assert payload["typ"] == "refresh"
        assert "iat" in payload
        assert "exp" in payload

    def test_refresh_token_has_long_default_lifetime(self, issuer):
        """Refresh token default exp ~30 days >> access token 1h."""
        access = issuer.verify_access_token(issuer.issue_access_token(sub="u"))
        refresh = issuer.verify_refresh_token(issuer.issue_refresh_token(sub="u"))
        # exp - iat for refresh (~2592000s) must exceed access (~3600s).
        assert (refresh["exp"] - refresh["iat"]) > (access["exp"] - access["iat"])
        assert (refresh["exp"] - refresh["iat"]) >= 2592000 - 5

    def test_verify_access_token_rejects_refresh_token(self, issuer):
        """A refresh token MUST NOT be usable as an access token."""
        refresh = issuer.issue_refresh_token(sub="user")
        with pytest.raises(jwt.InvalidTokenError):
            issuer.verify_access_token(refresh)

    def test_verify_refresh_token_rejects_access_token(self, issuer):
        """An access token MUST NOT be usable as a refresh token."""
        access = issuer.issue_access_token(sub="user")
        with pytest.raises(jwt.InvalidTokenError):
            issuer.verify_refresh_token(access)

    def test_verify_refresh_token_rejects_expired(self, issuer):
        """An expired refresh token is rejected with the standard PyJWT error."""
        token = issuer.issue_refresh_token(sub="user", expires_in_seconds=-10)
        with pytest.raises(jwt.ExpiredSignatureError):
            issuer.verify_refresh_token(token)

    def test_verify_refresh_token_fails_with_wrong_issuer(self, keys_dir):
        issuer1 = JWTIssuer(server_name="issuer-1", keys_dir=keys_dir)
        issuer2 = JWTIssuer(server_name="issuer-2", keys_dir=keys_dir)
        issuer2.public_key = issuer1.public_key

        token = issuer1.issue_refresh_token(sub="user")
        with pytest.raises(jwt.InvalidIssuerError):
            issuer2.verify_refresh_token(token)

    def test_verify_access_token_accepts_missing_typ(self, issuer):
        """Backward-compat: tokens issued before refresh support (no ``typ``) still verify.

        Re-encode a payload identical to ``issue_access_token`` but WITHOUT the
        ``typ`` claim, signed with the same private key, and assert
        ``verify_access_token`` accepts it.
        """
        import datetime

        import jwt as _jwt

        now = datetime.datetime.now(datetime.UTC)
        legacy_payload = {
            "iss": issuer.server_name,
            "aud": issuer.server_name,
            "sub": "legacy-user",
            "iat": now,
            "exp": now + datetime.timedelta(seconds=3600),
        }
        legacy_token = _jwt.encode(
            legacy_payload,
            issuer.private_key,
            algorithm="RS256",
            headers={"kid": "key-1"},
        )
        payload = issuer.verify_access_token(legacy_token)
        assert payload["sub"] == "legacy-user"
        assert "typ" not in payload
