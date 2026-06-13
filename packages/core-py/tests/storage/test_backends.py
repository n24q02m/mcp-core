"""Credential backend tests."""

from mcp_core.storage.backends import InMemoryBackend, LocalFsBackend


def test_inmemory_put_get_roundtrip():
    backend = InMemoryBackend()
    assert backend.get("k") is None
    backend.put("k", b"\x00\x01\x02")
    assert backend.get("k") == b"\x00\x01\x02"


def test_inmemory_delete_is_idempotent():
    backend = InMemoryBackend()
    backend.put("k", b"data")
    backend.delete("k")
    assert backend.get("k") is None
    backend.delete("k")  # second delete must not raise


def test_inmemory_keys_are_isolated():
    backend = InMemoryBackend()
    backend.put("a", b"value-a")
    backend.put("b", b"value-b")
    assert backend.get("a") == b"value-a"
    assert backend.get("b") == b"value-b"


def test_localfs_writes_under_home_plugin_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    backend = LocalFsBackend()
    backend.put("wet/config", b"blob")
    assert (tmp_path / ".wet-mcp" / "config.json").read_bytes() == b"blob"


def test_localfs_sub_path_and_get_delete(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    backend = LocalFsBackend()
    backend.put("wet/subs/u1/config", b"blob")
    assert (tmp_path / ".wet-mcp" / "subs" / "u1" / "config.json").read_bytes() == b"blob"
    assert backend.get("wet/subs/u1/config") == b"blob"
    backend.delete("wet/subs/u1/config")
    assert backend.get("wet/subs/u1/config") is None
