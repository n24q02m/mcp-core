"""HKDF-SHA256 key derivation.

Two distinct, domain-separated uses of HKDF-SHA256 live here:

1. ``derive_aes_key`` — relay-passphrase / ECDH path. Derives an AES-256 key
   from an ECDH shared secret using the human-readable passphrase as the HKDF
   salt and a fixed ``info`` of ``b"mcp-relay"``.
2. ``derive_jwt_signing_seed`` — OAuth signing-key path. Derives a 32-byte
   Ed25519 seed from the operator-supplied ``CREDENTIAL_SECRET`` using a
   per-server ``info`` label. This is a SECOND, intentional use of HKDF; the
   distinct ``info`` label provides cryptographic domain separation so the two
   purposes can never collide. Do NOT call ``derive_aes_key`` for the signing
   seed — its salt/info binding is wrong for this purpose.
"""

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_INFO = b"mcp-relay"
_JWT_SIGNING_INFO_PREFIX = "mcp-jwt-signing-key-v1:"


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


def derive_jwt_signing_seed(secret: str, server_name: str) -> bytes:
    """Derive a deterministic 32-byte Ed25519 seed for OAuth JWT signing.

    Used in HTTP multi-user mode (``CREDENTIAL_SECRET`` set) so every container
    replica converges on the SAME signing key without a shared volume or
    external secret store. The same ``(secret, server_name)`` always yields the
    same seed; different servers get domain-separated seeds via the ``info``
    label.

    Uses HKDF-SHA256 with:
    - IKM: ``secret`` (the operator-supplied ``CREDENTIAL_SECRET``)
    - salt: empty (``CREDENTIAL_SECRET`` is already high-entropy operator
      material; an HKDF salt adds nothing here and an empty salt keeps the
      output reproducible across replicas)
    - info: ``"mcp-jwt-signing-key-v1:<server_name>"``

    Args:
        secret: The operator-supplied root secret (``CREDENTIAL_SECRET``).
        server_name: The MCP server name (e.g. ``"wet-mcp"``).

    Returns:
        32-byte seed suitable for ``Ed25519PrivateKey.from_private_bytes``.
    """
    info = f"{_JWT_SIGNING_INFO_PREFIX}{server_name}".encode("utf-8")
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(secret.encode("utf-8"))
