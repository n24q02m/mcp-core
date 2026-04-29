"""Tests for ``sweep_stale_locks`` — TTL + PID liveness gate."""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mcp_core.lifecycle.lock import sweep_stale_locks


def _write_lock_with_age(path: Path, pid: int, port: int, age_hours: float = 0) -> None:
    ts = (datetime.now(timezone.utc) - timedelta(hours=age_hours)).isoformat()
    path.write_text(f"{pid}\n{port}\ntoken\n{ts}\n", encoding="utf-8")


def _write_6line_lock(path: Path, pid: int, port: int, age_hours: float, cred_state: str = "configured") -> None:
    """Write a 6-line D9 lock with spawned_at and last_activity_at both aged by age_hours."""
    ts = (datetime.now(timezone.utc) - timedelta(hours=age_hours)).isoformat()
    path.write_text(f"{pid}\n{port}\ntoken\n{ts}\n{cred_state}\n{ts}\n", encoding="utf-8")


def test_sweep_removes_locks_with_dead_pid(tmp_path):
    p1 = tmp_path / "demo-1001.lock"
    p2 = tmp_path / "demo-1002.lock"
    _write_lock_with_age(p1, 999999, 1001)
    _write_lock_with_age(p2, 999998, 1002)

    removed = sweep_stale_locks("demo", root=tmp_path)

    assert removed == 2
    assert not p1.exists()
    assert not p2.exists()


def test_sweep_removes_expired_lock_even_if_pid_alive(tmp_path):
    p = tmp_path / "demo-2001.lock"
    _write_lock_with_age(p, os.getpid(), 2001, age_hours=25)

    removed = sweep_stale_locks("demo", ttl_hours=24, root=tmp_path)

    assert removed == 1
    assert not p.exists()


def test_sweep_keeps_alive_lock_within_ttl(tmp_path):
    p = tmp_path / "demo-3001.lock"
    _write_lock_with_age(p, os.getpid(), 3001, age_hours=1)

    removed = sweep_stale_locks("demo", ttl_hours=24, root=tmp_path)

    assert removed == 0
    assert p.exists()


def test_sweep_only_targets_named_server(tmp_path):
    p_demo = tmp_path / "demo-4001.lock"
    p_other = tmp_path / "other-server-4002.lock"
    _write_lock_with_age(p_demo, 999999, 4001)
    _write_lock_with_age(p_other, 999999, 4002)

    removed = sweep_stale_locks("demo", root=tmp_path)

    assert removed == 1
    assert not p_demo.exists()
    assert p_other.exists()


def test_sweep_removes_legacy_3_line_locks(tmp_path):
    """Legacy format from pre-Wave-2 daemons cleaned on next sweep."""
    p = tmp_path / "demo-5001.lock"
    p.write_text("9999\n5001\ntoken\n", encoding="utf-8")  # 3 lines

    removed = sweep_stale_locks("demo", root=tmp_path)

    assert removed == 1
    assert not p.exists()


def test_sweep_returns_zero_when_locks_dir_missing(tmp_path):
    nonexistent = tmp_path / "no-such-dir"
    assert sweep_stale_locks("demo", root=nonexistent) == 0


def test_sweep_handles_corrupted_lock(tmp_path):
    p = tmp_path / "demo-6001.lock"
    p.write_text("garbage data not_a_pid\n", encoding="utf-8")

    removed = sweep_stale_locks("demo", root=tmp_path)

    assert removed == 1
    assert not p.exists()


def test_sweep_eleven_stale_locks_clears_all(tmp_path):
    """Regression test for the 2026-04-28 wet-mcp pile-up scenario where
    11 stale lock files accumulated in a single session."""
    for i in range(11):
        p = tmp_path / f"wet-mcp-{50000 + i}.lock"
        _write_lock_with_age(p, 999990 + i, 50000 + i)

    removed = sweep_stale_locks("wet-mcp", root=tmp_path)

    assert removed == 11
    assert list(tmp_path.glob("wet-mcp-*.lock")) == []


def test_sweep_stale_locks_removes_companion_sentinel_and_cache(tmp_path):
    """sweep_stale_locks cleans up .tools-list-changed and .tools.json next to a
    TTL-expired lock file (D17.3 companion cleanup)."""
    lock = tmp_path / "wet-mcp-12345.lock"
    # Use current PID so the lock passes the liveness check and falls through
    # to the TTL branch (configured + 25h old > 24h default TTL).
    _write_6line_lock(lock, os.getpid(), 12345, age_hours=25)

    sentinel = tmp_path / "wet-mcp-12345.tools-list-changed"
    sentinel.touch()
    cache = tmp_path / "wet-mcp-12345.tools.json"
    cache.write_text("{}")

    removed = sweep_stale_locks("wet-mcp", ttl_hours=24, root=tmp_path)

    assert removed >= 1
    assert not lock.exists()
    assert not sentinel.exists()
    assert not cache.exists()


def test_sweep_keeps_companions_when_lock_unlink_fails(tmp_path, monkeypatch):
    """When path.unlink() raises OSError on the lock file, companions are NOT
    cleaned up (avoids orphan-lock-pointing-to-deleted-cache state)."""
    lock = tmp_path / "wet-mcp-12346.lock"
    _write_6line_lock(lock, os.getpid(), 12346, age_hours=25)

    sentinel = tmp_path / "wet-mcp-12346.tools-list-changed"
    sentinel.touch()

    # Patch Path.unlink to fail only for .lock files.
    real_unlink = Path.unlink

    def _fail_lock_unlink(self: Path, missing_ok: bool = False) -> None:
        if self.suffix == ".lock":
            raise OSError("simulated unlink failure")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", _fail_lock_unlink)

    sweep_stale_locks("wet-mcp", ttl_hours=24, root=tmp_path)

    # Lock unlink failed → companion must still exist (no dangling cache).
    assert sentinel.exists()
