import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from mcp_core.oauth.jwt_issuer import JWTIssuer


def test_mkdir_uses_restricted_mode():
    """Verify that JWTIssuer creates the keys directory with mode=0o700."""
    with patch.object(Path, "mkdir") as mock_mkdir:
        with patch.object(Path, "chmod"):
            # We don't want it to actually create directories or generate keys for this test
            with patch("mcp_core.oauth.jwt_issuer.rsa.generate_private_key"):
                with patch("mcp_core.oauth.jwt_issuer.serialization.load_pem_private_key"):
                    with patch("mcp_core.oauth.jwt_issuer.serialization.load_pem_public_key"):
                        # Mock open to avoid writing files
                        with patch("builtins.open", MagicMock()):
                            JWTIssuer(server_name="test", keys_dir=Path("/tmp/fake-keys"))

        # Check if mkdir was called with mode=0o700
        found = False
        for call in mock_mkdir.call_args_list:
            if call.kwargs.get("mode") == 0o700:
                found = True
                break

        assert found, f"mkdir was not called with mode=0o700. Calls: {mock_mkdir.call_args_list}"


if os.name != "nt":

    def test_directory_permissions_creation(tmp_path):
        """Integration test: Verify directory permissions on creation."""
        keys_dir = tmp_path / "new_keys_dir"
        # Ensure it doesn't exist
        assert not keys_dir.exists()

        # We want to verify that it is SECURE during creation.
        # This is hard to test with just final state if chmod is also called.
        # But we can check if it works.
        JWTIssuer(server_name="test", keys_dir=keys_dir)

        assert keys_dir.exists()
        # Check permissions
        import stat

        mode = stat.S_IMODE(keys_dir.stat().st_mode)
        assert mode == 0o700
