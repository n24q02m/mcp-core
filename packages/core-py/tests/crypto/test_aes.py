"""Tests for AES-256-GCM encryption."""

import pytest
from cryptography.exceptions import InvalidTag

from mcp_core.crypto.aes import decrypt, encrypt
from mcp_core.crypto.kdf import derive_aes_key


def _make_key(passphrase: str = "test-passphrase") -> bytes:
    secret = bytes([0x0B] * 32)
    return derive_aes_key(secret, passphrase)


class TestAES256GCM:
    def test_encrypt_decrypt_roundtrip(self):
        key = _make_key()
        plaintext = "hello, mcp-relay!"

        ciphertext, iv, tag = encrypt(key, plaintext)
        decrypted = decrypt(key, ciphertext, iv, tag)

        assert decrypted == plaintext

    def test_iv_is_12_bytes(self):
        key = _make_key()
        _, iv, _ = encrypt(key, "test")

        assert isinstance(iv, bytes)
        assert len(iv) == 12

    def test_tag_is_16_bytes(self):
        key = _make_key()
        _, _, tag = encrypt(key, "test")

        assert isinstance(tag, bytes)
        assert len(tag) == 16

    def test_wrong_key_fails_to_decrypt(self):
        key1 = _make_key("key-one")
        key2 = _make_key("key-two")

        ciphertext, iv, tag = encrypt(key1, "secret data")

        with pytest.raises(InvalidTag):
            decrypt(key2, ciphertext, iv, tag)

    def test_tampered_ciphertext_fails_to_decrypt(self):
        key = _make_key()
        ciphertext, iv, tag = encrypt(key, "integrity check")

        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF

        with pytest.raises(InvalidTag):
            decrypt(key, bytes(tampered), iv, tag)

    def test_handles_empty_string(self):
        key = _make_key()
        ciphertext, iv, tag = encrypt(key, "")
        decrypted = decrypt(key, ciphertext, iv, tag)
        assert decrypted == ""

    def test_handles_unicode(self):
        key = _make_key()
        text = "Xin chao! Tieng Viet co dau"
        ciphertext, iv, tag = encrypt(key, text)
        decrypted = decrypt(key, ciphertext, iv, tag)
        assert decrypted == text
