"""Tests for async cross-process lifecycle lock."""

from __future__ import annotations

import os
import asyncio
from pathlib import Path
import uuid
import pytest

from mcp_core.lifecycle.lock import (
    AsyncLifecycleLock,
    async_refresh_lock_timestamp,
    async_sweep_stale_locks,
    async_write_lock_file,
    _parse_lock_text,
)


@pytest.fixture
def lock_root(tmp_path: Path) -> Path:
    """Per-test lock directory."""
    root = tmp_path / "locks"
    root.mkdir(parents=True, exist_ok=True)
    return root


@pytest.fixture
def unique_name() -> str:
    """Unique server name."""
    return f"test-async-srv-{uuid.uuid4().hex[:8]}"


@pytest.mark.asyncio
async def test_async_acquires_and_releases(lock_root: Path, unique_name: str) -> None:
    lock = AsyncLifecycleLock(name=unique_name, port=9000, root=lock_root)
    lock_file = lock_root / f"{unique_name}-9000.lock"

    async with lock:
        assert lock_file.exists(), "lock file must exist while held"
        content = lock_file.read_text(encoding="utf-8")
        meta = _parse_lock_text(content)
        assert meta is not None
        assert meta.pid == os.getpid()
        assert meta.port == 9000

    assert not lock_file.exists(), "lock file must be removed after release"


@pytest.mark.asyncio
async def test_async_refresh_lock_timestamp(lock_root: Path, unique_name: str) -> None:
    lock = AsyncLifecycleLock(name=unique_name, port=9000, root=lock_root)
    lock_file = lock_root / f"{unique_name}-9000.lock"

    async with lock:
        old_content = lock_file.read_text(encoding="utf-8")
        old_meta = _parse_lock_text(old_content)

        await asyncio.sleep(0.1)
        await async_refresh_lock_timestamp(lock_file)

        new_content = lock_file.read_text(encoding="utf-8")
        new_meta = _parse_lock_text(new_content)

        assert new_meta is not None
        assert old_meta is not None
        assert new_meta.spawned_at > old_meta.spawned_at


@pytest.mark.asyncio
async def test_async_sweep_stale_locks(lock_root: Path, unique_name: str) -> None:
    # Create a stale lock file (backdated)
    lock_file = lock_root / f"{unique_name}-9000.lock"
    payload = f"{os.getpid()}\n9000\ntoken\n2020-01-01T00:00:00+00:00\n"
    lock_file.write_text(payload.ljust(512, " "), encoding="utf-8")

    assert lock_file.exists()

    removed = await async_sweep_stale_locks(unique_name, ttl_hours=1, root=lock_root)
    assert removed == 1
    assert not lock_file.exists()


@pytest.mark.asyncio
async def test_async_write_lock_file(lock_root: Path, unique_name: str) -> None:
    path = await async_write_lock_file(unique_name, 9001, "test-token", root=lock_root)
    assert path.exists()
    assert path.name == f"{unique_name}-9001.lock"

    content = path.read_text(encoding="utf-8")
    meta = _parse_lock_text(content)
    assert meta is not None
    assert meta.pid == os.getpid()
    assert meta.port == 9001
    assert meta.token == "test-token"
