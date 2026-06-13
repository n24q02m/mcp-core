"""Credential backend tests."""

import pytest

from mcp_core.storage.backends import (
    CfKvBackend,
    InMemoryBackend,
    LocalFsBackend,
    backend_from_env,
)


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


def test_localfs_rejects_traversal_sub(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    backend = LocalFsBackend()
    with pytest.raises(ValueError):
        backend.put("wet/subs/../config", b"x")
    with pytest.raises(ValueError):
        backend.get("wet/subs/../config")
    with pytest.raises(ValueError):
        backend.delete("wet/subs/../config")


def test_localfs_rejects_traversal_plugin(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    backend = LocalFsBackend()
    with pytest.raises(ValueError):
        backend.put("../config", b"x")


def test_localfs_allows_dot_in_sub(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    backend = LocalFsBackend()
    backend.put("wet/subs/u.1/config", b"blob")
    assert backend.get("wet/subs/u.1/config") == b"blob"


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


class _StatusHttp:
    """HTTP stub returning a fixed (status, body) for any request."""

    def __init__(self, status, body=b""):
        self.status = status
        self.body = body

    def request(self, method, url, data, headers):
        return (self.status, self.body)


def test_cfkv_backend_roundtrip_via_http():
    fake = _FakeHttp()
    backend = CfKvBackend(base_url="http://kv.internal", http=fake)
    assert backend.get("wet/config") is None
    backend.put("wet/config", b"blob")
    assert backend.get("wet/config") == b"blob"
    backend.delete("wet/config")
    assert backend.get("wet/config") is None


def test_cfkv_get_raises_on_server_error():
    backend = CfKvBackend(base_url="http://kv.internal", http=_StatusHttp(500, b"<html>oops</html>"))
    with pytest.raises(RuntimeError):
        backend.get("wet/config")


def test_cfkv_get_raises_on_unauthorized():
    backend = CfKvBackend(base_url="http://kv.internal", http=_StatusHttp(401, b""))
    with pytest.raises(RuntimeError):
        backend.get("wet/config")


def test_cfkv_get_returns_none_on_404():
    backend = CfKvBackend(base_url="http://kv.internal", http=_StatusHttp(404, b""))
    assert backend.get("wet/config") is None


def test_cfkv_delete_raises_on_server_error():
    backend = CfKvBackend(base_url="http://kv.internal", http=_StatusHttp(500, b""))
    with pytest.raises(RuntimeError):
        backend.delete("wet/config")


def test_cfkv_delete_ignores_404():
    backend = CfKvBackend(base_url="http://kv.internal", http=_StatusHttp(404, b""))
    backend.delete("wet/config")  # must not raise


def test_backend_from_env_default_is_localfs(monkeypatch):
    monkeypatch.delenv("MCP_STORAGE_BACKEND", raising=False)
    assert isinstance(backend_from_env(), LocalFsBackend)


def test_backend_from_env_selects_cfkv(monkeypatch):
    monkeypatch.setenv("MCP_STORAGE_BACKEND", "cf-kv")
    monkeypatch.setenv("MCP_KV_BASE_URL", "http://kv.internal")
    assert isinstance(backend_from_env(), CfKvBackend)


def test_backend_from_env_cfkv_requires_base_url(monkeypatch):
    monkeypatch.setenv("MCP_STORAGE_BACKEND", "cf-kv")
    monkeypatch.delenv("MCP_KV_BASE_URL", raising=False)
    with pytest.raises(ValueError, match="MCP_KV_BASE_URL"):
        backend_from_env()


def test_backend_from_env_unknown_kind_raises(monkeypatch):
    monkeypatch.setenv("MCP_STORAGE_BACKEND", "bogus")
    with pytest.raises(ValueError):
        backend_from_env()


def test_cfkv_put_raises_on_server_error():
    backend = CfKvBackend(base_url="http://kv.internal", http=_StatusHttp(500))
    with pytest.raises(RuntimeError):
        backend.put("wet/config", b"x")


class _RaisingHttp:
    """HTTP stub whose request always raises a transport-level error."""

    def request(self, *args, **kwargs):
        raise OSError("econnrefused")


def test_cfkv_propagates_transport_errors():
    backend = CfKvBackend(base_url="http://kv.internal", http=_RaisingHttp())
    with pytest.raises(OSError):
        backend.get("wet/config")
    with pytest.raises(OSError):
        backend.put("wet/config", b"x")
    with pytest.raises(OSError):
        backend.delete("wet/config")
