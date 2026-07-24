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
    _cache_dir,
    cache_filename,
    persist_tools_cache,
    load_tools_cache,
)


def test_cache_dir_returns_path():
    """Verify _cache_dir returns a Path object pointing to the expected location."""
    path = _cache_dir()
    assert isinstance(path, Path)
    assert ".config" in str(path)
    assert "mcp" in str(path)
    assert "cache" in str(path)


def test_cache_filename_includes_versions():
    name = cache_filename("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0")
    assert name == "wet-mcp-55317-2.28.4-1.11.0.tools.json"


def test_persist_then_load_match_versions(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    tools = [{"name": "search", "description": "..."}]
    persist_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0", tools=tools)
    loaded = load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0")
    assert loaded == tools


def test_persist_then_load_empty_tools(tmp_path, monkeypatch):
    """Verify that an empty tool list is correctly cached and retrieved."""
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    tools = []
    persist_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0", tools=tools)
    loaded = load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0")
    assert loaded == []


def test_load_returns_none_on_version_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    persist_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0", tools=[{"name": "search"}])
    # Mismatch srv_version
    assert load_tools_cache("wet-mcp", 55317, srv_version="2.29.0", core_version="1.11.0") is None
    # Mismatch core_version
    assert load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.12.0") is None


def test_load_returns_none_on_internal_version_mismatch(tmp_path, monkeypatch):
    """Test when the file exists but the JSON payload has mismatched versions."""
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    # Manually write a file with mismatched internal versions
    name = cache_filename("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0")
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"tools": [], "srv_version": "wrong", "core_version": "1.11.0"})
    path.write_text(payload, encoding="utf-8")

    assert load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0") is None


def test_load_returns_none_on_invalid_tools_type(tmp_path, monkeypatch):
    """Test when the 'tools' key in the JSON payload is not a list."""
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    name = cache_filename("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0")
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"tools": "not a list", "srv_version": "2.28.4", "core_version": "1.11.0"})
    path.write_text(payload, encoding="utf-8")

    assert load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0") is None


def test_load_returns_none_on_corrupted_json(tmp_path, monkeypatch):
    """Test when the cache file contains invalid JSON."""
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    name = cache_filename("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0")
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ corrupted }", encoding="utf-8")

    assert load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0") is None


def test_load_returns_none_on_read_error(tmp_path, monkeypatch):
    """Test when reading the cache file raises an OSError."""
    monkeypatch.setattr("mcp_core.transport.cache._cache_dir", lambda: tmp_path)

    name = cache_filename("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0")
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}", encoding="utf-8")

    def fake_read_text(self, encoding=None):
        raise OSError("Read failure")

    monkeypatch.setattr(Path, "read_text", fake_read_text)

    assert load_tools_cache("wet-mcp", 55317, srv_version="2.28.4", core_version="1.11.0") is None


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


def test_atomic_write_creates_with_correct_mode(tmp_path, monkeypatch):
    """Verify that _atomic_write creates the temporary file with mode 0o600."""
    from mcp_core.transport.cache import _atomic_write
    import os

    # Mock os.open to verify mode, but still actually create a file descriptor
    original_open = os.open
    open_called_with_mode = None

    def fake_open(path, flags, mode=0o777):
        nonlocal open_called_with_mode
        open_called_with_mode = mode
        return original_open(path, flags, mode)

    monkeypatch.setattr(os, "open", fake_open)

    path = tmp_path / "test.json"
    _atomic_write(path, "content")

    assert path.read_text() == "content"
    assert open_called_with_mode == 0o600


def test_cache_traversal_sanitization():
    malicious_name = "../../etc/passwd"
    filename = cache_filename(malicious_name, 80, "1.0", "1.0")

    # It should no longer be a traversal path
    assert "/" not in filename
    assert "\\" not in filename
    assert filename == "______etc_passwd-80-1.0-1.0.tools.json"

    cache_dir = Path("/tmp/mcp-cache")
    full_path = cache_dir / filename

    # The resulting path MUST be under cache_dir
    assert full_path.parent == cache_dir


def test_dangerous_chars_sanitization():
    malicious_name = "server:name*with?chars"
    filename = cache_filename(malicious_name, 80, "1.0", "1.0")
    assert filename == "server_name_with_chars-80-1.0-1.0.tools.json"


def test_version_sanitization():
    filename = cache_filename("server", 80, "1.0/../2.0", "v1.0")
    assert filename == "server-80-1.0____2.0-v1.0.tools.json"


def test_cache_filename_absolute_path():
    """Verify that absolute paths are sanitized."""
    filename = cache_filename("/etc/passwd", 80, "1.0", "1.0")
    assert not filename.startswith("/")
    assert filename == "_etc_passwd-80-1.0-1.0.tools.json"


def test_cache_filename_null_bytes():
    """Verify that null bytes are sanitized."""
    filename = cache_filename("server\0.json", 80, "1.0", "1.0")
    assert "\0" not in filename
    assert filename == "server_.json-80-1.0-1.0.tools.json"


def test_cache_filename_neuters_dot_dot():
    """Verify that '..' sequences are neutered."""
    filename = cache_filename("..", 80, "..", "..")
    assert ".." not in filename
    assert filename == "__-80-__-__.tools.json"


def test_cache_filename_windows_style_paths():
    """Verify that Windows-style paths are sanitized."""
    filename = cache_filename("C:\\Windows\\System32\\config", 80, "1.0", "1.0")
    assert "\\" not in filename
    assert ":" not in filename
    assert filename == "C__Windows_System32_config-80-1.0-1.0.tools.json"
