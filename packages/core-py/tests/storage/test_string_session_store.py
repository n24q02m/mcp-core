"""StringSession seam: KV-persisted Telethon session string with save-on-change."""

from urllib.parse import unquote

from mcp_core.storage.backends import CfKvBackend, InMemoryBackend
from mcp_core.storage.string_session_store import (
    SaveOnChangeStringSession,
    StringSessionStore,
)


class _FakeKvHttp:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    def request(self, method, url, data=None, headers=None):
        key = unquote(url.rsplit("/", 1)[-1])
        if method == "PUT":
            self.store[key] = data or b""
            return (200, b"")
        if method == "GET":
            return (200, self.store[key]) if key in self.store else (404, b"")
        if method == "DELETE":
            existed = key in self.store
            self.store.pop(key, None)
            return (200, b"") if existed else (404, b"")
        raise AssertionError(method)


def test_string_session_roundtrip_inmemory(monkeypatch):
    monkeypatch.setenv("CREDENTIAL_SECRET", "k")
    mem = InMemoryBackend()
    StringSessionStore("telegram", "u1", backend=mem).save("1AaBbCc==")
    blob = mem.get("telegram/subs/u1/session")
    assert blob is not None and blob != b"1AaBbCc=="
    assert StringSessionStore("telegram", "u1", backend=mem).load() == "1AaBbCc=="


def test_string_session_missing_returns_none(monkeypatch):
    monkeypatch.setenv("CREDENTIAL_SECRET", "k")
    assert StringSessionStore("telegram", "u1", backend=InMemoryBackend()).load() is None


def test_string_session_multi_user_isolation(monkeypatch):
    monkeypatch.setenv("CREDENTIAL_SECRET", "k")
    mem = InMemoryBackend()
    StringSessionStore("telegram", "u1", backend=mem).save("AAA")
    StringSessionStore("telegram", "u2", backend=mem).save("BBB")
    assert mem.get("telegram/subs/u1/session") != mem.get("telegram/subs/u2/session")
    assert StringSessionStore("telegram", "u1", backend=mem).load() == "AAA"
    assert StringSessionStore("telegram", "u2", backend=mem).load() == "BBB"


def test_string_session_cfkv_roundtrip(monkeypatch):
    monkeypatch.setenv("CREDENTIAL_SECRET", "k")
    backend = CfKvBackend(base_url="http://kv.internal", http=_FakeKvHttp())
    StringSessionStore("telegram", "u1", backend=backend).save("ZZZ")
    assert StringSessionStore("telegram", "u1", backend=backend).load() == "ZZZ"


def test_save_on_change_fires_sink_on_save():
    saved: list[str] = []
    sess = SaveOnChangeStringSession(sink=saved.append)
    out = sess.save()
    assert isinstance(out, str)
    assert saved == [out]


def test_save_on_change_seeds_from_existing_string():
    seed = SaveOnChangeStringSession().save()
    sess = SaveOnChangeStringSession(seed, sink=lambda _s: None)
    assert sess.save() == seed
