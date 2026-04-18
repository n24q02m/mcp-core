"""Tests for machine ID and username detection."""

import os
from unittest.mock import patch

from mcp_core.storage.machine_id import get_machine_id, get_username


class TestGetMachineId:
    def test_returns_non_empty_string(self):
        # Clear cache before test to ensure consistent results
        get_machine_id.cache_clear()
        mid = get_machine_id()
        assert mid
        assert isinstance(mid, str)
        assert len(mid) > 0

    def test_returns_consistent_value(self):
        # Clear cache before test
        get_machine_id.cache_clear()
        id1 = get_machine_id()
        id2 = get_machine_id()
        assert id1 == id2

    def test_caching_works(self):
        # Clear cache before test
        get_machine_id.cache_clear()

        with patch("platform.system", return_value="Linux") as mock_system:
            # We also need to mock the file open since it's Linux
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value.read.return_value = "test-machine-id"

                # First call
                id1 = get_machine_id()
                assert id1 == "test-machine-id"
                assert mock_system.call_count == 1

                # Second call - should use cache
                id2 = get_machine_id()
                assert id2 == "test-machine-id"
                assert mock_system.call_count == 1


class TestGetUsername:
    def test_returns_non_empty_string(self):
        username = get_username()
        assert username
        assert isinstance(username, str)
        assert len(username) > 0

    def test_matches_current_os_user(self):
        username = get_username()
        expected = os.environ.get("USER") or os.environ.get("USERNAME")
        if expected:
            assert username == expected
