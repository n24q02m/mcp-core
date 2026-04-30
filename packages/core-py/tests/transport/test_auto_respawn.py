"""Tests for the bridge auto-respawn flow (D8, Task 1.11).

Covers:
- ``MAX_RESPAWN_PER_CALL_ID`` constant exported by ``smart_stdio``.
- ``daemon_respawn`` lock-acquire + spawn + wait-ready code path with
  monkeypatched primitives so no real subprocess starts.
- ``BridgeAutoRespawn`` per-bridge tracker capping respawn attempts per
  ``tool_call_id`` and expiring entries after the TTL window.
"""

from __future__ import annotations

import pytest

from mcp_core.transport.smart_stdio import (
    BridgeAutoRespawn,
    MAX_RESPAWN_PER_CALL_ID,
    daemon_respawn,
)


class _FakeLock:
    """Minimal stand-in for ``filelock.FileLock`` covering the parts the
    production code actually exercises. Returns ``self`` from
    ``acquire`` so the ``with`` block has a context manager to enter; no
    real OS lock is taken."""

    def __init__(self) -> None:
        self.acquired = False
        self.acquire_calls: list[float | int | None] = []

    def acquire(self, timeout: float | int | None = 10):
        self.acquire_calls.append(timeout)
        self.acquired = True
        return self

    def release(self) -> None:
        self.acquired = False

    # Context manager protocol so ``with _respawn_lock.acquire(...)`` works.
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


def test_max_respawn_constant() -> None:
    assert MAX_RESPAWN_PER_CALL_ID == 1


def test_daemon_respawn_acquires_lock_then_spawns(monkeypatch: pytest.MonkeyPatch) -> None:
    spawned: list[str] = []
    fake_lock = _FakeLock()

    monkeypatch.setattr("mcp_core.transport.smart_stdio._respawn_lock", fake_lock)
    monkeypatch.setattr(
        "mcp_core.transport.smart_stdio._spawn_daemon_detached",
        lambda srv: spawned.append(srv) or "",
    )
    monkeypatch.setattr(
        "mcp_core.transport.smart_stdio._wait_daemon_ready",
        lambda srv, timeout=60: True,
    )
    # ``daemon_is_alive`` is consulted twice: the inner double-check after
    # acquiring the lock (must be False so we go through the spawn path) and
    # implicitly via ``_wait_daemon_ready`` (already short-circuited above).
    monkeypatch.setattr(
        "mcp_core.transport.smart_stdio.daemon_is_alive",
        lambda srv: False,
    )
    monkeypatch.setattr(
        "mcp_core.transport.smart_stdio.daemon_relay_url",
        lambda srv: "http://127.0.0.1:55321/",
    )

    url = daemon_respawn("demo")

    assert url == "http://127.0.0.1:55321/"
    assert spawned == ["demo"]
    assert fake_lock.acquire_calls == [10]


def test_bridge_auto_respawn_tracks_call_id() -> None:
    tracker = BridgeAutoRespawn()
    assert tracker.can_respawn("call-1") is True
    tracker.mark_respawned("call-1")
    # Once marked, a second attempt within the TTL window is blocked.
    assert tracker.can_respawn("call-1") is False
    # Different call ids are tracked independently.
    assert tracker.can_respawn("call-2") is True


def test_bridge_auto_respawn_expires_after_5_min(monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_core.transport.smart_stdio as smart_stdio

    tracker = BridgeAutoRespawn()
    monkeypatch.setattr(smart_stdio.time, "time", lambda: 1000.0)
    tracker.mark_respawned("call-1")

    # Six minutes later, the entry should expire and respawn becomes allowed.
    monkeypatch.setattr(smart_stdio.time, "time", lambda: 1000.0 + 6 * 60)
    assert tracker.can_respawn("call-1") is True
