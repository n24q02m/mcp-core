"""Tests for the smart-stdio capabilities cache.

The cache lets `run_smart_stdio_proxy` answer `initialize` / `tools/list`
immediately, without waiting for the HTTP daemon to come up. This is the
"transparent bridge" property: Claude Code sees the full tool surface within
~1s of session start.
"""

from pathlib import Path

from mcp_core.transport.smart_stdio import (
    cache_path_for_lock,
    load_capabilities_cache,
    persist_capabilities_cache,
)


def test_cache_path_lives_next_to_lock(tmp_path):
    lock = tmp_path / ".config" / "mcp" / "locks" / "demo-1234.lock"
    cache = cache_path_for_lock(lock)
    assert cache.name == "demo-1234.tools.json"
    assert cache.parent == lock.parent


def test_persist_and_load_roundtrip(tmp_path):
    lock = tmp_path / "demo-1234.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    capabilities = {"tools": {"listChanged": False}, "experimental": {}}
    tools = [
        {"name": "echo", "description": "Echo input", "inputSchema": {"type": "object"}},
        {"name": "ping", "description": "Ping", "inputSchema": {"type": "object"}},
    ]
    persist_capabilities_cache(lock, "demo", "1.9.0", capabilities, tools)

    cache = load_capabilities_cache(lock)
    assert cache is not None
    assert cache["serverInfo"]["name"] == "demo"
    assert cache["serverInfo"]["version"] == "1.9.0"
    assert cache["capabilities"] == capabilities
    assert cache["tools"] == tools


def test_load_returns_none_when_no_cache(tmp_path):
    lock = tmp_path / "demo-9999.lock"
    assert load_capabilities_cache(lock) is None


def test_load_returns_none_for_corrupt_cache(tmp_path):
    lock = tmp_path / "demo-1234.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    cache_path = cache_path_for_lock(lock)
    cache_path.write_text("not valid json {", encoding="utf-8")
    assert load_capabilities_cache(lock) is None


def test_persist_overwrites_existing_cache(tmp_path):
    lock = tmp_path / "demo-1234.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    persist_capabilities_cache(lock, "demo", "1.0.0", {}, [{"name": "old"}])
    persist_capabilities_cache(
        lock,
        "demo",
        "1.1.0",
        {"tools": {}},
        [{"name": "new"}],
    )

    cache = load_capabilities_cache(lock)
    assert cache is not None
    assert cache["serverInfo"]["version"] == "1.1.0"
    assert cache["tools"] == [{"name": "new"}]


def test_load_validates_version_when_requested(tmp_path, monkeypatch):
    lock = tmp_path / "demo-1234.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    persist_capabilities_cache(lock, "demo", "1.0.0", {}, [])

    monkeypatch.setattr(
        "mcp_core.transport.smart_stdio._current_mcp_core_version",
        lambda: "2.0.0",
    )
    assert load_capabilities_cache(lock, validate_version=True) is None
    # Without the flag, stale cache still loads.
    assert load_capabilities_cache(lock) is not None


def test_load_returns_cache_when_version_matches(tmp_path, monkeypatch):
    lock = tmp_path / "demo-1234.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    persist_capabilities_cache(lock, "demo", "1.0.0", {}, [])

    monkeypatch.setattr(
        "mcp_core.transport.smart_stdio._current_mcp_core_version",
        lambda: "1.0.0",
    )
    assert load_capabilities_cache(lock, validate_version=True) is not None


def test_cache_path_for_lock_handles_non_lock_suffix(tmp_path: Path):
    """Defensive: function should not crash on weird input names."""
    lock = tmp_path / "demo.txt"
    cache = cache_path_for_lock(lock)
    assert cache.suffix == ".json"
    assert cache.parent == lock.parent
