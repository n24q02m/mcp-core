"""Credential backend tests."""

from mcp_core.storage.backends import CfKvBackend, InMemoryBackend, LocalFsBackend


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


class _FakeHttp:
    """In-memory HTTP stub keyed by the URL's last path segment."""

    def __init__(self):
        self.store: dict[str, bytes] = {}

    def request(self, method, url, data, headers):
        seg = url.rsplit("/", 1)[-1]
        if method == "PUT":
            self.store[seg] = data
            return (200, b"")
        if method == "GET":
            if seg in self.store:
                return (200, self.store[seg])
            return (404, b"")
        if method == "DELETE":
            self.store.pop(seg, None)
            return (200, b"")
        raise AssertionError(f"unexpected method {method}")


def test_cfkv_backend_roundtrip_via_http():
    fake = _FakeHttp()
    backend = CfKvBackend(base_url="http://kv.internal", http=fake)
    assert backend.get("wet/config") is None
    backend.put("wet/config", b"blob")
    assert backend.get("wet/config") == b"blob"
    backend.delete("wet/config")
    assert backend.get("wet/config") is None
