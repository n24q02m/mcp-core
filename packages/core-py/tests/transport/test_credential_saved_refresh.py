"""D17.2 — cache file rewritten with full tool list when credential saved."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.mark.asyncio
async def test_authorize_post_refreshes_capabilities_cache(tmp_path, monkeypatch):
    from mcp_core.transport import local_server
    from mcp_core.transport.smart_stdio import cache_path_for_lock

    # Pre-populate stale cache with reduced tool list (simulating startup-time
    # snapshot when cred state was awaiting_setup).
    lock = tmp_path / "wet-mcp-55317.lock"
    lock.write_text("123\n55317\ntok\n2026-04-29T00:00:00\nunconfigured\n2026-04-29T00:00:00\n")
    cache = cache_path_for_lock(lock)
    cache.write_text(
        json.dumps(
            {
                "serverInfo": {"name": "wet-mcp", "version": "1.11.1"},
                "capabilities": {"tools": {"listChanged": True}},
                "tools": [{"name": "config__open_relay"}],
            }
        )
    )

    # Mock daemon mcp.list_tools() to return full list post-config.
    fake_mcp = MagicMock()
    fake_mcp.list_tools = AsyncMock(
        return_value=[
            MagicMock(model_dump=lambda: {"name": "search"}),
            MagicMock(model_dump=lambda: {"name": "fact_check"}),
            MagicMock(model_dump=lambda: {"name": "config__open_relay"}),
        ]
    )
    monkeypatch.setattr(local_server, "_get_mcp_for_server", lambda name: fake_mcp)

    # Simulate write_config side effect — call the post-save refresh hook.
    await local_server._refresh_capabilities_cache_after_save("wet-mcp", lock)

    refreshed = json.loads(cache.read_text())
    tool_names = [t["name"] for t in refreshed["tools"]]
    assert tool_names == ["search", "fact_check", "config__open_relay"]
