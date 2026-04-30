"""D17.3 — daemon touches sentinel file when tool list changes."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest


def _sentinel_path(lock_path: Path) -> Path:
    return lock_path.with_suffix(".tools-list-changed")


@pytest.mark.asyncio
async def test_refresh_touches_list_changed_sentinel(tmp_path, monkeypatch):
    from mcp_core.transport import local_server

    lock = tmp_path / "wet-mcp-55317.lock"
    lock.write_text("123\n55317\ntok\n2026-04-29T00:00:00\nconfigured\n2026-04-29T00:00:00\n")

    fake_mcp = MagicMock()
    fake_mcp.list_tools = AsyncMock(
        return_value=[
            MagicMock(model_dump=lambda **kwargs: {"name": "search"}),
        ]
    )
    monkeypatch.setattr(local_server, "_get_mcp_for_server", lambda name: fake_mcp)

    sentinel = _sentinel_path(lock)
    assert not sentinel.exists()

    await local_server._refresh_capabilities_cache_after_save("wet-mcp", lock)

    assert sentinel.exists()
    mtime_first = sentinel.stat().st_mtime

    # Second refresh should bump mtime (sentinel is "touch on change" pattern).
    import time

    time.sleep(0.05)
    await local_server._refresh_capabilities_cache_after_save("wet-mcp", lock)
    mtime_second = sentinel.stat().st_mtime
    assert mtime_second > mtime_first


@pytest.mark.asyncio
async def test_bridge_poller_emits_notification_on_sentinel_touch(tmp_path):
    """D17.3 — bridge stdout receives notification within 500ms of sentinel touch."""
    from mcp_core.transport.smart_stdio import _poll_tools_list_changed_sentinel

    lock = tmp_path / "wet-mcp-55317.lock"
    lock.write_text("123\n55317\ntok\n2026-04-29T00:00:00\nconfigured\n2026-04-29T00:00:00\n")
    sentinel = lock.with_suffix(".tools-list-changed")

    notifications = []

    async def fake_emit():
        notifications.append("changed")

    import asyncio

    poll_task = asyncio.create_task(_poll_tools_list_changed_sentinel(lock, fake_emit))

    # Wait one poll cycle, then touch sentinel
    await asyncio.sleep(0.3)
    sentinel.touch()

    # Wait up to 600ms for the poller to detect
    for _ in range(12):
        await asyncio.sleep(0.05)
        if notifications:
            break

    poll_task.cancel()
    assert notifications == ["changed"]
