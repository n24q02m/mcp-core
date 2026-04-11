"""Tests for HKDF-SHA256 key derivation."""

from mcp_core.crypto.kdf import derive_aes_key


def _make_shared_secret(byte: int = 0x0B) -> bytes:
    return bytes([byte] * 32)


class TestHKDFSHA256:
    def test_returns_32_byte_key(self):
        key = derive_aes_key(_make_shared_secret(), "test-passphrase")
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_different_passphrases_produce_different_keys(self):
        secret = _make_shared_secret()
        key1 = derive_aes_key(secret, "passphrase-one")
        key2 = derive_aes_key(secret, "passphrase-two")

        assert key1.hex() != key2.hex()

    def test_same_inputs_produce_same_key(self):
        key1 = derive_aes_key(_make_shared_secret(), "same-passphrase")
        key2 = derive_aes_key(_make_shared_secret(), "same-passphrase")

        assert key1.hex() == key2.hex()

    def test_different_secrets_produce_different_keys(self):
        key1 = derive_aes_key(_make_shared_secret(0x0B), "passphrase")
        key2 = derive_aes_key(_make_shared_secret(0x0C), "passphrase")

        assert key1.hex() != key2.hex()
