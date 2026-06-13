"""Credential backend tests."""

from mcp_core.storage.backends import InMemoryBackend


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
