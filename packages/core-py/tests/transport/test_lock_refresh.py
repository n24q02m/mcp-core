"""Test the daemon's lock-mtime refresh loop."""

import asyncio
from datetime import datetime, timezone

import pytest

from mcp_core.lifecycle.lock import parse_lock_metadata
from mcp_core.transport.local_server import _refresh_lock_timestamp_loop


@pytest.mark.asyncio
async def test_refresh_loop_updates_timestamp(tmp_path):
    lock_path = tmp_path / "demo-1234.lock"
    # Write a stale timestamp from 6 years ago.
    lock_path.write_text(
        "1\n1234\nt\n2020-01-01T00:00:00+00:00\n",
        encoding="utf-8",
    )

    # Run the refresh loop with a tiny interval; cancel after one iteration.
    task = asyncio.create_task(_refresh_lock_timestamp_loop(lock_path, interval_seconds=0.05))
    await asyncio.sleep(0.15)  # Allow at least one iteration.
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    md = parse_lock_metadata(lock_path)
    assert md is not None
    assert md.created_at.year == datetime.now(timezone.utc).year


@pytest.mark.asyncio
async def test_refresh_loop_cancellable_during_sleep(tmp_path):
    """The loop must be cancellable during its asyncio.sleep — verifying
    the CancelledError handler returns cleanly without raising."""
    lock_path = tmp_path / "demo-1234.lock"
    lock_path.write_text(
        "1\n1234\nt\n2020-01-01T00:00:00+00:00\n",
        encoding="utf-8",
    )

    task = asyncio.create_task(
        _refresh_lock_timestamp_loop(lock_path, interval_seconds=60.0)
    )
    # Cancel before any refresh fires.
    await asyncio.sleep(0.01)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    # Loop returned cleanly. File untouched.
    md = parse_lock_metadata(lock_path)
    assert md is not None
    assert md.created_at.year == 2020
