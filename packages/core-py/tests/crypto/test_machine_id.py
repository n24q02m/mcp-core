"""Tests for machine ID and username detection."""

import os

from mcp_core.crypto.machine_id import get_machine_id, get_username


class TestGetMachineId:
    def test_returns_non_empty_string(self):
        mid = get_machine_id()
        assert mid
        assert isinstance(mid, str)
        assert len(mid) > 0

    def test_returns_consistent_value(self):
        id1 = get_machine_id()
        id2 = get_machine_id()
        assert id1 == id2


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
