"""PBKDF2-based key derivation + AES-256-GCM file encryption.

Format: [12-byte IV][ciphertext + 16-byte GCM tag]
Compatible with the TypeScript implementation.
"""

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_SALT = b"mcp-relay-config"
_EXPORT_SALT = b"mcp-relay-export"
PBKDF2_ITERATIONS = 600_000
LEGACY_PBKDF2_ITERATIONS = 100_000


def derive_file_key(
    machine_id: str, username: str, iterations: int = PBKDF2_ITERATIONS
) -> bytes:
    """Derive AES-256 key from machine ID and username using PBKDF2.

    Args:
        machine_id: Machine identifier string.
        username: OS username string.
        iterations: Number of PBKDF2 iterations.

    Returns:
        32-byte AES key.
    """
    key_material = f"{machine_id}:{username}".encode()
    return hashlib.pbkdf2_hmac("sha256", key_material, _SALT, iterations, dklen=32)


def derive_passphrase_key(
    passphrase: str, iterations: int = PBKDF2_ITERATIONS
) -> bytes:
    """Derive AES-256 key from passphrase using PBKDF2 (for export/import).

    Args:
        passphrase: User-provided passphrase.
        iterations: Number of PBKDF2 iterations.

    Returns:
        32-byte AES key.
    """
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), _EXPORT_SALT, iterations, dklen=32
    )


def encrypt_data(key: bytes, plaintext: str) -> bytes:
    """Encrypt plaintext with AES-256-GCM.

    Format: [12-byte IV][ciphertext + tag]

    Args:
        key: 32-byte AES key.
        plaintext: String to encrypt.

    Returns:
        Bytes in format [IV][ciphertext+tag].
    """
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + tag
    encrypted = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    return iv + encrypted


def decrypt_data(key: bytes, data: bytes) -> str:
    """Decrypt data encrypted with encrypt_data.

    Args:
        key: 32-byte AES key.
        data: Bytes in format [12-byte IV][ciphertext+tag].

    Returns:
        Decrypted plaintext string.

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails.
    """
    iv = data[:12]
    ciphertext_and_tag = data[12:]
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext_and_tag, None)
    return plaintext_bytes.decode("utf-8")
