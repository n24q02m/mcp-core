"""Tests for the version-keyed tools cache (D10).

Cache filename includes both server version and core version, so an upgrade on
either side invalidates the cache. Persist must not raise on filesystem errors
(this is the root cause for crg #384, where a Windows write failure crashed the
bridge).
"""

from mcp_core.transport.cache import (
    cache_filename,
    persist_tools_cache,
    load_tools_cache,
)


def test_cache_filename_includes_versions():
    name = cache_filename("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0")
    assert name == "wet-mcp-55317-2.28.4-1.11.0.tools.json"


def test_persist_then_load_match_versions(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    tools = [{"name": "search", "description": "..."}]
    persist_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0", tools=tools)
    loaded = load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0")
    assert loaded == tools


def test_load_returns_none_on_version_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    persist_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0", tools=[{"name": "search"}])
    # Mismatch srv_version
    assert load_tools_cache("wet-mcp", 55317, srv_version="2.29.0", core_version="1.11.0") is None
    # Mismatch core_version
    assert load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.12.0") is None


def test_persist_atomic_replace_on_existing(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    persist_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0", tools=[{"name": "search"}])
    persist_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0", tools=[{"name": "search2"}])
    loaded = load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0")
    assert loaded == [{"name": "search2"}]


def test_persist_silent_on_oserror(tmp_path, monkeypatch):
    """D10 root cause for #384 -- Windows write may fail; silently skip cache, no exception."""
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    def fake_atomic_write(path, content):
        raise PermissionError("Windows access denied")

    monkeypatch.setattr("mcp_core.transport.cache._atomic_write", fake_atomic_write)
    # Must not raise
    persist_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0", tools=[])
    # And cache stays absent (load returns None)
    assert load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0") is None
