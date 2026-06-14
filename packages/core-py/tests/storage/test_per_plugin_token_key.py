from mcp_core.storage.backends import InMemoryBackend, LocalFsBackend
from mcp_core.storage.per_plugin_store import PerPluginStore


def test_token_subkey_routes_to_tokens_namespace(monkeypatch):
    monkeypatch.setenv("CREDENTIAL_SECRET", "k")
    mem = InMemoryBackend()
    store = PerPluginStore("wet", "u1", backend=mem, sub_key="tokens/google_drive")
    store.save({"access_token": "abc"})
    assert mem.get("wet/subs/u1/tokens/google_drive") is not None
    assert mem.get("wet/subs/u1/config") is None
    assert PerPluginStore("wet", "u1", backend=mem, sub_key="tokens/google_drive").load() == {"access_token": "abc"}


def test_token_subkey_single_user(monkeypatch):
    monkeypatch.setenv("CREDENTIAL_SECRET", "k")
    mem = InMemoryBackend()
    PerPluginStore("wet", backend=mem, sub_key="tokens/google_drive").save({"access_token": "x"})
    assert mem.get("wet/tokens/google_drive") is not None


def test_localfs_accepts_token_key(tmp_path, monkeypatch):
    monkeypatch.setattr("mcp_core.storage.backends.Path.home", lambda: tmp_path)
    b = LocalFsBackend()
    b.put("wet/tokens/google_drive", b"blob")
    assert (tmp_path / ".wet-mcp" / "tokens" / "google_drive.json").read_bytes() == b"blob"
    b.put("wet/subs/u1/tokens/google_drive", b"blob2")
    assert (tmp_path / ".wet-mcp" / "subs" / "u1" / "tokens" / "google_drive.json").exists()


def test_localfs_token_key_rejects_traversal(tmp_path, monkeypatch):
    import pytest

    monkeypatch.setattr("mcp_core.storage.backends.Path.home", lambda: tmp_path)
    b = LocalFsBackend()
    with pytest.raises(ValueError):
        b.put("wet/tokens/../escape", b"x")
    with pytest.raises(ValueError):
        b.put("wet/subs/u1/tokens/../../escape", b"x")
