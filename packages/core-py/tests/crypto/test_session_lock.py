"""Tests for file-based session lock."""

import json
import time

import pytest

from mcp_core.crypto.session_lock import (
    SessionInfo,
    acquire_session_lock,
    release_session_lock,
    set_lock_dir,
    write_session_lock,
)


@pytest.fixture(autouse=True)
def _temp_lock_dir(tmp_path):
    set_lock_dir(str(tmp_path))
    yield tmp_path
    set_lock_dir(None)


class TestAcquireSessionLock:
    async def test_returns_none_when_no_lock_exists(self):
        result = await acquire_session_lock("test-server")
        assert result is None

    async def test_returns_session_info_when_lock_is_fresh(self):
        info = SessionInfo(
            session_id="abc123",
            relay_url="https://relay.example.com/setup?s=abc123#k=key&p=pass",
            created_at=time.time(),
        )
        await write_session_lock("test-server", info)

        result = await acquire_session_lock("test-server")
        assert result is not None
        assert result.session_id == "abc123"
        assert result.relay_url == info.relay_url
        assert result.created_at == info.created_at

    async def test_returns_none_when_lock_is_expired(self, _temp_lock_dir):
        info = SessionInfo(
            session_id="old-session",
            relay_url="https://relay.example.com/setup?s=old",
            created_at=time.time() - 700,  # 700 seconds ago (> 600s default)
        )
        await write_session_lock("test-server", info)

        result = await acquire_session_lock("test-server")
        assert result is None

        # Lock file should be cleaned up
        lock_file = _temp_lock_dir / "relay-session-test-server.lock"
        assert not lock_file.exists()

    async def test_respects_custom_max_age(self):
        info = SessionInfo(
            session_id="short-lived",
            relay_url="https://relay.example.com/setup?s=short",
            created_at=time.time() - 5,  # 5 seconds ago
        )
        await write_session_lock("test-server", info)

        # Should be expired with 3s max age
        result = await acquire_session_lock("test-server", max_age_s=3.0)
        assert result is None

        # Should be valid with 10s max age
        info2 = SessionInfo(
            session_id="short-lived-2",
            relay_url="https://relay.example.com/setup?s=short2",
            created_at=time.time() - 5,
        )
        await write_session_lock("test-server", info2)
        result = await acquire_session_lock("test-server", max_age_s=10.0)
        assert result is not None
        assert result.session_id == "short-lived-2"

    async def test_returns_none_on_corrupt_lock_file(self, _temp_lock_dir):
        lock_file = _temp_lock_dir / "relay-session-test-server.lock"
        lock_file.write_text("not valid json", encoding="utf-8")

        result = await acquire_session_lock("test-server")
        assert result is None

        # Corrupt file should be cleaned up
        assert not lock_file.exists()

    async def test_returns_none_on_missing_fields(self, _temp_lock_dir):
        lock_file = _temp_lock_dir / "relay-session-test-server.lock"
        lock_file.write_text(json.dumps({"session_id": "partial"}), encoding="utf-8")

        result = await acquire_session_lock("test-server")
        assert result is None


class TestWriteSessionLock:
    async def test_creates_lock_file(self, _temp_lock_dir):
        info = SessionInfo(
            session_id="new-session",
            relay_url="https://relay.example.com/setup?s=new",
            created_at=1234567890.0,
        )
        await write_session_lock("test-server", info)

        lock_file = _temp_lock_dir / "relay-session-test-server.lock"
        assert lock_file.exists()

        data = json.loads(lock_file.read_text(encoding="utf-8"))
        assert data == {
            "session_id": "new-session",
            "relay_url": "https://relay.example.com/setup?s=new",
            "created_at": 1234567890.0,
        }

    async def test_overwrites_existing_lock(self, _temp_lock_dir):
        now = time.time()
        info1 = SessionInfo(
            session_id="first",
            relay_url="https://relay.example.com/first",
            created_at=now,
        )
        await write_session_lock("test-server", info1)

        info2 = SessionInfo(
            session_id="second",
            relay_url="https://relay.example.com/second",
            created_at=now,
        )
        await write_session_lock("test-server", info2)

        result = await acquire_session_lock("test-server")
        assert result is not None
        assert result.session_id == "second"

    async def test_creates_parent_directories(self, tmp_path):
        nested_dir = str(tmp_path / "nested" / "dir")
        set_lock_dir(nested_dir)

        info = SessionInfo(
            session_id="nested",
            relay_url="https://relay.example.com/nested",
            created_at=time.time(),
        )
        await write_session_lock("test-server", info)

        result = await acquire_session_lock("test-server")
        assert result is not None
        assert result.session_id == "nested"

        set_lock_dir(str(tmp_path))


class TestReleaseSessionLock:
    async def test_removes_lock_file(self, _temp_lock_dir):
        info = SessionInfo(
            session_id="to-release",
            relay_url="https://relay.example.com/release",
            created_at=time.time(),
        )
        await write_session_lock("test-server", info)

        lock_file = _temp_lock_dir / "relay-session-test-server.lock"
        assert lock_file.exists()

        await release_session_lock("test-server")
        assert not lock_file.exists()

    async def test_no_error_when_lock_does_not_exist(self):
        # Should not raise
        await release_session_lock("nonexistent-server")

    async def test_different_servers_have_independent_locks(self, _temp_lock_dir):
        info1 = SessionInfo(
            session_id="server-a",
            relay_url="https://relay.example.com/a",
            created_at=time.time(),
        )
        info2 = SessionInfo(
            session_id="server-b",
            relay_url="https://relay.example.com/b",
            created_at=time.time(),
        )
        await write_session_lock("server-a", info1)
        await write_session_lock("server-b", info2)

        await release_session_lock("server-a")

        assert await acquire_session_lock("server-a") is None
        result = await acquire_session_lock("server-b")
        assert result is not None
        assert result.session_id == "server-b"
