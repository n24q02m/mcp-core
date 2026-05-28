"""Tests for the version-keyed tools cache (D10).

Cache filename includes both server version and core version, so an upgrade on
either side invalidates the cache. Persist must not raise on filesystem errors
(this is the root cause for crg #384, where a Windows write failure crashed the
bridge).
"""

import json
import logging
from pathlib import Path
from mcp_core.transport.cache import (
    cache_filename,
    persist_tools_cache,
    load_tools_cache,
    _cache_dir,
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


def test_load_returns_none_on_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)
    # File doesn't exist
    assert load_tools_cache("wet-mcp", 55317, srv_version="2.29.0", core_version="1.11.0") is None


def test_load_returns_none_on_version_mismatch_in_payload(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    srv, port, sv, cv = "wet-mcp", 55317, "2.28.4", "1.11.0"
    name = cache_filename(srv, port, sv, cv)
    path = tmp_path / name

    # Mismatch srv_version in payload
    payload = {"tools": [], "srv_version": "wrong", "core_version": cv}
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_tools_cache(srv, port, sv, cv) is None

    # Mismatch core_version in payload
    payload = {"tools": [], "srv_version": sv, "core_version": "wrong"}
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_tools_cache(srv, port, sv, cv) is None


def test_persist_atomic_replace_on_existing(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    persist_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0", tools=[{"name": "search"}])
    persist_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0", tools=[{"name": "search2"}])
    loaded = load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0")
    assert loaded == [{"name": "search2"}]


def test_persist_silent_on_oserror(tmp_path, monkeypatch, caplog):
    """D10 root cause for #384 — Windows write may fail; silently skip cache, no exception."""
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    def fake_atomic_write(path, content):
        raise PermissionError("Windows access denied")

    monkeypatch.setattr("mcp_core.transport.cache._atomic_write", fake_atomic_write)

    with caplog.at_level(logging.DEBUG):
        # Must not raise
        persist_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0", tools=[])

    assert "Failed to persist capabilities cache for wet-mcp: Windows access denied" in caplog.text
    # And cache stays absent (load returns None)
    assert load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0") is None


def test_load_tools_cache_corrupted_json(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)
    name = cache_filename("wet-mcp", 55317, "1.0", "1.0")
    path = tmp_path / name
    path.write_text("corrupted json", encoding="utf-8")

    assert load_tools_cache("wet-mcp", 55317, "1.0", "1.0") is None


def test_load_tools_cache_oserror(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)
    name = cache_filename("wet-mcp", 55317, "1.0", "1.0")
    path = tmp_path / name
    path.write_text("{}", encoding="utf-8")

    def fake_read_text(self, encoding=None, errors=None):
        raise OSError("Read error")

    monkeypatch.setattr("pathlib.Path.read_text", fake_read_text)

    assert load_tools_cache("wet-mcp", 55317, "1.0", "1.0") is None


def test_load_tools_cache_invalid_tools_type(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)
    payload = {"srv_version": "1.0", "core_version": "1.0", "tools": "not a list"}
    name = cache_filename("wet-mcp", 55317, "1.0", "1.0")
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert load_tools_cache("wet-mcp", 55317, "1.0", "1.0") is None


def test_cache_dir_logic(monkeypatch):
    fake_home = Path("/fake/home")
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)
    assert _cache_dir() == fake_home / ".config" / "mcp" / "cache"
