"""Tests for ECDH P-256 key exchange."""

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from mcp_core.crypto.ecdh import (
    derive_shared_secret,
    export_public_key,
    generate_key_pair,
    import_public_key,
)


class TestGenerateKeyPair:
    def test_generates_valid_keypair(self):
        private_key, public_key = generate_key_pair()
        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)


class TestExportImportPublicKey:
    def test_exports_and_imports_public_key_as_base64url(self):
        _, public_key = generate_key_pair()
        exported = export_public_key(public_key)
        assert isinstance(exported, str)
        assert len(exported) > 0

        imported = import_public_key(exported)
        assert isinstance(imported, EllipticCurvePublicKey)

    def test_roundtrip_preserves_key(self):
        _, public_key = generate_key_pair()
        exported = export_public_key(public_key)
        imported = import_public_key(exported)
        re_exported = export_public_key(imported)
        assert exported == re_exported


class TestDeriveSharedSecret:
    def test_derives_identical_shared_secret_on_both_sides(self):
        alice_priv, alice_pub = generate_key_pair()
        bob_priv, bob_pub = generate_key_pair()

        secret_a = derive_shared_secret(alice_priv, bob_pub)
        secret_b = derive_shared_secret(bob_priv, alice_pub)

        assert secret_a.hex() == secret_b.hex()
        assert len(secret_a) == 32

    def test_derives_different_secrets_with_different_keypairs(self):
        alice_priv, _ = generate_key_pair()
        _, bob_pub = generate_key_pair()
        _, charlie_pub = generate_key_pair()

        secret_ab = derive_shared_secret(alice_priv, bob_pub)
        secret_ac = derive_shared_secret(alice_priv, charlie_pub)

        assert secret_ab.hex() != secret_ac.hex()
