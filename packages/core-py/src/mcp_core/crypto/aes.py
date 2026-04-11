"""AES-256-GCM encryption and decryption."""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(key: bytes, plaintext: str) -> tuple[bytes, bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM.

    Args:
        key: 32-byte AES key.
        plaintext: String to encrypt.

    Returns:
        Tuple of (ciphertext, iv, tag) where:
        - ciphertext: encrypted data (without tag)
        - iv: 12-byte initialization vector
        - tag: 16-byte authentication tag
    """
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + 16-byte tag appended
    combined = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    ciphertext = combined[:-16]
    tag = combined[-16:]
    return ciphertext, iv, tag


def decrypt(key: bytes, ciphertext: bytes, iv: bytes, tag: bytes) -> str:
    """Decrypt ciphertext with AES-256-GCM.

    Args:
        key: 32-byte AES key.
        ciphertext: Encrypted data (without tag).
        iv: 12-byte initialization vector.
        tag: 16-byte authentication tag.

    Returns:
        Decrypted plaintext string.

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails.
    """
    aesgcm = AESGCM(key)
    # AESGCM.decrypt expects ciphertext + tag concatenated
    combined = ciphertext + tag
    plaintext_bytes = aesgcm.decrypt(iv, combined, None)
    return plaintext_bytes.decode("utf-8")
