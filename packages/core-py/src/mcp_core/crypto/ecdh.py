"""ECDH P-256 key exchange."""

import base64

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


def generate_key_pair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate an ECDH P-256 key pair.

    Returns:
        Tuple of (private_key, public_key).
    """
    private_key = generate_private_key(SECP256R1())
    return private_key, private_key.public_key()


def export_public_key(public_key: EllipticCurvePublicKey) -> str:
    """Export public key as base64url string (raw uncompressed point).

    Returns:
        Base64url-encoded string (no padding).
    """
    raw = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def import_public_key(b64url: str) -> EllipticCurvePublicKey:
    """Import public key from base64url string (raw uncompressed point).

    Args:
        b64url: Base64url-encoded public key (no padding).

    Returns:
        EC public key object.
    """
    # Add padding if needed
    padded = b64url + "=" * (-len(b64url) % 4)
    raw = base64.urlsafe_b64decode(padded)
    return ec.EllipticCurvePublicKey.from_encoded_point(SECP256R1(), raw)


def derive_shared_secret(
    private_key: EllipticCurvePrivateKey,
    public_key: EllipticCurvePublicKey,
) -> bytes:
    """Derive shared secret (32 bytes) from ECDH key exchange.

    Args:
        private_key: Local private key.
        public_key: Remote public key.

    Returns:
        32-byte shared secret.
    """
    return private_key.exchange(ECDH(), public_key)


def export_private_key(private_key: EllipticCurvePrivateKey) -> str:
    """Export private key as base64url string.

    Returns:
        Base64url-encoded string (no padding).
    """
    raw = private_key.private_numbers().private_value
    val_bytes = raw.to_bytes((raw.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("ascii")


def import_private_key(b64url: str) -> EllipticCurvePrivateKey:
    """Import private key from base64url string.

    Args:
        b64url: Base64url-encoded private key (no padding).

    Returns:
        EC private key object.
    """
    padded = b64url + "=" * (-len(b64url) % 4)
    raw = base64.urlsafe_b64decode(padded)
    val = int.from_bytes(raw, byteorder="big")
    return ec.derive_private_key(val, SECP256R1())
