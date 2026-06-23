"""Tests for PBKDF2 key derivation + AES-256-GCM file encryption."""

import pytest
from cryptography.exceptions import InvalidTag

from mcp_core.storage.encryption import (
    LEGACY_PBKDF2_ITERATIONS,
    decrypt_data,
    derive_file_key,
    derive_passphrase_key,
    encrypt_data,
)

test_salt = b"\x01" * 16


class TestDeriveFileKey:
    def test_returns_32_byte_key(self):
        key = derive_file_key("machine-123", "alice", test_salt)
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_same_inputs_produce_same_key(self):
        key1 = derive_file_key("id-abc", "bob", test_salt)
        key2 = derive_file_key("id-abc", "bob", test_salt)

        encrypted = encrypt_data(key1, "test data")
        decrypted = decrypt_data(key2, encrypted)
        assert decrypted == "test data"

    def test_different_machine_id_produces_different_key(self):
        key1 = derive_file_key("machine-A", "user", test_salt)
        key2 = derive_file_key("machine-B", "user", test_salt)

        encrypted = encrypt_data(key1, "secret")
        with pytest.raises(InvalidTag):
            decrypt_data(key2, encrypted)

    def test_different_username_produces_different_key(self):
        key1 = derive_file_key("machine-1", "alice", test_salt)
        key2 = derive_file_key("machine-1", "bob", test_salt)

        encrypted = encrypt_data(key1, "secret")
        with pytest.raises(InvalidTag):
            decrypt_data(key2, encrypted)

    def test_different_salt_produces_different_key(self):
        salt2 = b"\x02" * 16
        key1 = derive_file_key("m", "u", test_salt)
        key2 = derive_file_key("m", "u", salt2)

        encrypted = encrypt_data(key1, "secret")
        with pytest.raises(InvalidTag):
            decrypt_data(key2, encrypted)


class TestDerivePassphraseKey:
    def test_returns_32_byte_key(self):
        key = derive_passphrase_key("my secret passphrase", test_salt)
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_same_passphrase_produces_same_key(self):
        passphrase = "password123"
        key1 = derive_passphrase_key(passphrase, test_salt)
        key2 = derive_passphrase_key(passphrase, test_salt)
        assert key1 == key2

    def test_different_passphrase_produces_different_key(self):
        key1 = derive_passphrase_key("passphrase-A", test_salt)
        key2 = derive_passphrase_key("passphrase-B", test_salt)

        encrypted = encrypt_data(key1, "top secret")
        with pytest.raises(InvalidTag):
            decrypt_data(key2, encrypted)


class TestEncryptDecryptRoundtrip:
    def test_encrypts_and_decrypts_plain_text(self):
        key = derive_file_key("test-machine", "test-user", test_salt)
        plaintext = "hello, config!"

        encrypted = encrypt_data(key, plaintext)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 12  # IV + ciphertext

        decrypted = decrypt_data(key, encrypted)
        assert decrypted == plaintext

    def test_handles_empty_string(self):
        key = derive_file_key("m", "u", test_salt)
        encrypted = encrypt_data(key, "")
        decrypted = decrypt_data(key, encrypted)
        assert decrypted == ""

    def test_handles_unicode_text(self):
        key = derive_file_key("m", "u", test_salt)
        text = "Xin chao the gioi! Tieng Viet co dau"
        encrypted = encrypt_data(key, text)
        decrypted = decrypt_data(key, encrypted)
        assert decrypted == text

    def test_produces_different_ciphertext_each_time(self):
        key = derive_file_key("m", "u", test_salt)
        enc1 = encrypt_data(key, "same")
        enc2 = encrypt_data(key, "same")
        assert enc1 != enc2

    def test_wrong_key_fails_to_decrypt(self):
        key1 = derive_file_key("m1", "u1", test_salt)
        key2 = derive_file_key("m2", "u2", test_salt)

        encrypted = encrypt_data(key1, "secret data")
        with pytest.raises(InvalidTag):
            decrypt_data(key2, encrypted)


class TestPBKDF2Iterations:
    def test_different_iterations_produce_different_keys(self):
        # Use hardcoded distinct values to verify iteration sensitivity
        key_1 = derive_file_key("m", "u", test_salt, 1000)
        key_2 = derive_file_key("m", "u", test_salt, 2000)

        encrypted = encrypt_data(key_1, "secret")
        with pytest.raises(InvalidTag):
            decrypt_data(key_2, encrypted)

    def test_legacy_key_can_decrypt_legacy_data(self):
        key_legacy = derive_file_key("m", "u", test_salt, LEGACY_PBKDF2_ITERATIONS)
        plaintext = "migration test"
        encrypted = encrypt_data(key_legacy, plaintext)
        decrypted = decrypt_data(key_legacy, encrypted)
        assert decrypted == plaintext

    def test_passphrase_key_different_iterations(self):
        # Use hardcoded distinct values to verify iteration sensitivity
        key_1 = derive_passphrase_key("pass", test_salt, 1000)
        key_2 = derive_passphrase_key("pass", test_salt, 2000)

        encrypted = encrypt_data(key_1, "secret")
        with pytest.raises(InvalidTag):
            decrypt_data(key_2, encrypted)
