"""HKDF-SHA256 key derivation."""

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_INFO = b"mcp-relay"


def derive_aes_key(shared_secret: bytes, passphrase: str) -> bytes:
    """Derive a 32-byte AES-256 key from shared secret and passphrase.

    Uses HKDF-SHA256 with:
    - salt: passphrase encoded as UTF-8
    - info: b"mcp-relay"

    Args:
        shared_secret: 32-byte shared secret from ECDH.
        passphrase: Human-readable passphrase string.

    Returns:
        32-byte AES key.
    """
    salt = passphrase.encode("utf-8")
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        info=_INFO,
    )
    return hkdf.derive(shared_secret)
