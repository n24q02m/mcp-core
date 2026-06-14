import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_core.crypto import derive_jwt_signing_seed

_VECTORS = json.loads((Path(__file__).parents[1] / "fixtures" / "crypto-vectors.json").read_text())


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def test_seed_is_32_bytes():
    seed = derive_jwt_signing_seed("any-secret", "some-server")
    assert isinstance(seed, bytes)
    assert len(seed) == 32


def test_seed_is_deterministic():
    a = derive_jwt_signing_seed("secret-1", "wet-mcp")
    b = derive_jwt_signing_seed("secret-1", "wet-mcp")
    assert a == b


def test_seed_domain_separated_by_server_name():
    a = derive_jwt_signing_seed("secret-1", "wet-mcp")
    b = derive_jwt_signing_seed("secret-1", "mnemo-mcp")
    assert a != b


def test_seed_domain_separated_by_secret():
    a = derive_jwt_signing_seed("secret-1", "wet-mcp")
    b = derive_jwt_signing_seed("secret-2", "wet-mcp")
    assert a != b


def test_seed_is_one_way_not_equal_to_secret():
    secret = "test-credential-secret-value"
    seed = derive_jwt_signing_seed(secret, "wet-mcp")
    assert seed != secret.encode("utf-8")


def test_matches_cross_language_parity_vector():
    v = _VECTORS["jwt_signing_seed"]
    seed = derive_jwt_signing_seed(v["credential_secret"], v["server_name"])
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    raw_pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert _b64url(raw_pub) == v["okp_x"]
    kid = _b64url(hashlib.sha256(raw_pub).digest())[:16]
    assert kid == v["kid"]
