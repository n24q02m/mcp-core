"""Per-plugin encrypted credential store tests."""

import json
import logging
import os
from pathlib import Path

import pytest

from mcp_core.storage.backends import InMemoryBackend
from mcp_core.storage.per_plugin_store import PerPluginStore, _cred_path


@pytest.fixture
def store_factory(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    return lambda plugin, sub=None: PerPluginStore(plugin, sub)


def test_save_and_load_stdio_mode(store_factory):
    store = store_factory("test-plugin")
    payload = {"GEMINI_API_KEY": "sk-fake-key"}
    store.save(payload)
    assert store.load() == payload


def test_save_and_load_multi_user(store_factory, monkeypatch):
    monkeypatch.setenv("CREDENTIAL_SECRET", "test-master-secret")
    store_a = store_factory("test-plugin", sub="user-uuid-a")
    store_b = store_factory("test-plugin", sub="user-uuid-b")
    store_a.save({"key": "value-a"})
    store_b.save({"key": "value-b"})
    assert store_a.load() == {"key": "value-a"}
    assert store_b.load() == {"key": "value-b"}


def test_path_layout(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    store_stdio = PerPluginStore("foo")
    store_multi = PerPluginStore("foo", sub="abc-123")
    assert store_stdio.cred_path == tmp_path / ".foo-mcp" / "config.json"
    assert store_multi.cred_path == tmp_path / ".foo-mcp" / "subs" / "abc-123" / "config.json"


def test_path_traversal_protection():
    with pytest.raises(ValueError, match="Invalid plugin_name"):
        _cred_path("../evil", None)
    with pytest.raises(ValueError, match="Invalid sub"):
        _cred_path("plugin", "../../evil")
    with pytest.raises(ValueError, match="Invalid plugin_name"):
        _cred_path("", None)
    with pytest.raises(ValueError, match="Invalid sub"):
        _cred_path("plugin", "")
    # "." is allowed in the char class (version-style segments), so a bare ".."
    # with no "/" is caught only by the explicit dotdot guard.
    with pytest.raises(ValueError, match="Invalid sub"):
        _cred_path("plugin", "a..b")
    with pytest.raises(ValueError, match="Invalid plugin_name"):
        _cred_path("plug..in", None)


def test_token_urlsafe_sub_accepted():
    # The OAuth AS mints sub = secrets.token_urlsafe(16); its base64url alphabet
    # includes "_" and "-". Both must be accepted, else ~half of all per-sub
    # credential saves fail with "Invalid sub" (regression: telegram CF, 2026-06-17).
    sub = "oG5FyoFE-RWqI_aciDl4zA"  # contains both "-" and "_"
    path = _cred_path("better-telegram", sub)
    assert path.name == "config.json"
    assert sub in path.parts  # the sub is a single, intact path segment
    # "/" separators stay rejected so path traversal protection is unaffected.
    with pytest.raises(ValueError, match="Invalid sub"):
        _cred_path("plugin", "a/b")


def test_underscore_sub_round_trips(store_factory, monkeypatch):
    monkeypatch.setenv("CREDENTIAL_SECRET", "test-master-secret")
    store = store_factory("plugin", sub="ab_cd-EF_gh")
    store.save({"token": "value"})
    assert store.load() == {"token": "value"}


def test_clear(store_factory):
    store = store_factory("test-plugin")
    store.save({"x": 1})
    store.clear()
    assert store.load() is None


def test_file_perm_0600(store_factory, tmp_path):
    if os.name == "nt":
        pytest.skip("perm test posix-only")
    store = store_factory("test-plugin")
    store.save({"x": 1})
    mode = store.cred_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_cross_sub_no_read(store_factory, monkeypatch):
    monkeypatch.setenv("CREDENTIAL_SECRET", "test-master-secret")
    store_a = store_factory("plugin", sub="sub-a")
    store_a.save({"secret": "for-a"})
    store_b = store_factory("plugin", sub="sub-b")
    assert store_b.load() is None


def test_multi_user_requires_credential_secret(store_factory, monkeypatch):
    monkeypatch.delenv("CREDENTIAL_SECRET", raising=False)
    store = store_factory("plugin", sub="some-sub")
    with pytest.raises(RuntimeError, match="CREDENTIAL_SECRET"):
        store.save({"k": "v"})


def test_per_plugin_store_uses_injected_backend(monkeypatch):
    monkeypatch.setenv("CREDENTIAL_SECRET", "test-master")
    mem = InMemoryBackend()
    PerPluginStore("wet", "u1", backend=mem).save({"JINA_AI_API_KEY": "k"})
    blob = mem.get("wet/subs/u1/config")
    assert blob is not None
    assert blob != json.dumps({"JINA_AI_API_KEY": "k"}).encode("utf-8")
    assert PerPluginStore("wet", "u1", backend=mem).load() == {"JINA_AI_API_KEY": "k"}


def test_load_returns_none_on_tampered_ciphertext(store_factory):
    """Tampered or corrupt file -> load() returns None (defensive UX)."""
    store = store_factory("test-plugin")
    store.save({"key": "value"})
    # Corrupt the ciphertext: flip last byte
    blob = store.cred_path.read_bytes()
    tampered = blob[:-1] + bytes([blob[-1] ^ 0xFF])
    store.cred_path.write_bytes(tampered)
    assert store.load() is None


def test_load_corrupt_blob_logs_loudly(store_factory, caplog):
    """Decrypt failure (tampered/corrupt ciphertext) must log loudly, not silently."""
    store = store_factory("demo")
    store.save({"k": "v"})
    # Corrupt the ciphertext on disk
    cfg = Path.home() / ".demo-mcp" / "config.json"
    cfg.write_bytes(b"\x00" * 40)
    with caplog.at_level(logging.ERROR):
        assert store.load() is None  # API giữ nguyên
    assert any("corrupt" in r.message.lower() for r in caplog.records)
    assert "demo/config" in caplog.text  # nói rõ KEY nào, không lộ nội dung


def test_load_truncated_blob_logs_loudly(store_factory, caplog):
    """Blob shorter than the nonce (13 bytes) is a torn write, not silent absence."""
    store = store_factory("demo")
    store._backend.put(store.cred_key, b"\x00" * 5)
    with caplog.at_level(logging.ERROR):
        assert store.load() is None  # API giữ nguyên
    assert any("corrupt" in r.message.lower() for r in caplog.records)
    assert "demo/config" in caplog.text  # nói rõ KEY nào, không lộ nội dung


def test_machine_key_write_is_atomic(monkeypatch, tmp_path):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    store = PerPluginStore("demo")

    # Only crash the .secret rename, not config.json's -- otherwise the
    # config write's own (already-atomic) replace() would raise first and
    # mask whether the machine-key write is atomic.
    real_replace = Path.replace

    def boom(self, target):
        if target.name == ".secret":
            raise OSError("simulated crash at rename")
        return real_replace(self, target)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("pathlib.Path.replace", boom)
        with pytest.raises(OSError):
            store.save({"k": "v"})  # first save generates the machine key

    secret = Path.home() / ".demo-mcp" / ".secret"
    assert not secret.exists() or len(secret.read_bytes()) == 32  # không bao giờ torn
    store.save({"k": "v"})  # recover sạch sau crash
    assert store.load() == {"k": "v"}
