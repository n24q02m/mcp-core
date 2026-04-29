"""D9 — extended lock format (6 lines) + hybrid TTL sweep.

The lock file gains two trailing fields beyond the 4-line v1 format:

::

    {pid}
    {port}
    {token}
    {spawned_at_iso8601_utc}
    {cred_state}              # "configured" | "unconfigured"
    {last_activity_at_iso8601_utc}

so the sweep can apply a different TTL depending on whether the daemon
ever finished credential setup. An idle setup daemon (cred_state =
"unconfigured") is reaped after 30 minutes; a configured long-lived
daemon stays for 24 hours past its last activity bump.
"""

from datetime import datetime, timedelta, timezone

from mcp_core.lifecycle.lock import (
    LIFECYCLE_TTL_CONFIGURED,
    LIFECYCLE_TTL_UNCONFIGURED,
    LockMetadata,
    parse_lock,
    serialize_lock,
    sweep_stale_locks,
)


def test_serialize_6_lines() -> None:
    meta = LockMetadata(
        pid=12345,
        port=33333,
        token="abc-token",
        spawned_at=datetime(2026, 4, 29, 10, 0, tzinfo=timezone.utc),
        cred_state="configured",
        last_activity_at=datetime(2026, 4, 29, 11, 0, tzinfo=timezone.utc),
    )
    lines = serialize_lock(meta).rstrip("\n").split("\n")
    assert lines[0] == "12345"
    assert lines[1] == "33333"
    assert lines[2] == "abc-token"
    assert lines[3] == "2026-04-29T10:00:00+00:00"
    assert lines[4] == "configured"
    assert lines[5] == "2026-04-29T11:00:00+00:00"


def test_parse_6_lines_modern() -> None:
    raw = "12345\n33333\nabc-token\n2026-04-29T10:00:00+00:00\nconfigured\n2026-04-29T11:00:00+00:00\n"
    meta = parse_lock(raw)
    assert meta.pid == 12345
    assert meta.cred_state == "configured"


def test_parse_4_lines_legacy_assume_configured() -> None:
    """Legacy v1 lock missing cred_state + last_activity_at → assume configured."""
    raw = "12345\n33333\nabc-token\n2026-04-29T10:00:00+00:00\n"
    meta = parse_lock(raw)
    assert meta.cred_state == "configured"
    assert meta.last_activity_at == meta.spawned_at


def test_sweep_removes_unconfigured_after_30_min(tmp_path, monkeypatch) -> None:
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir()
    monkeypatch.setattr("mcp_core.lifecycle.lock._lock_dir", lambda: lock_dir)
    monkeypatch.setattr("mcp_core.lifecycle.lock._is_alive", lambda meta: True)

    old = datetime.now(timezone.utc) - timedelta(minutes=31)
    meta = LockMetadata(pid=999, port=1234, token="t", spawned_at=old, cred_state="unconfigured", last_activity_at=old)
    (lock_dir / "demo-1234.lock").write_text(serialize_lock(meta), encoding="utf-8")

    terminated: list[int] = []
    monkeypatch.setattr("mcp_core.lifecycle.lock._terminate_daemon", lambda pid: terminated.append(pid))

    removed = sweep_stale_locks("demo")

    assert removed == 1
    assert terminated == [999]
    assert not (lock_dir / "demo-1234.lock").exists()


def test_sweep_keeps_configured_under_24h(tmp_path, monkeypatch) -> None:
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir()
    monkeypatch.setattr("mcp_core.lifecycle.lock._lock_dir", lambda: lock_dir)
    monkeypatch.setattr("mcp_core.lifecycle.lock._is_alive", lambda meta: True)

    fresh = datetime.now(timezone.utc) - timedelta(hours=23)
    meta = LockMetadata(
        pid=999, port=1234, token="t", spawned_at=fresh, cred_state="configured", last_activity_at=fresh
    )
    (lock_dir / "demo-1234.lock").write_text(serialize_lock(meta), encoding="utf-8")

    monkeypatch.setattr("mcp_core.lifecycle.lock._terminate_daemon", lambda pid: None)

    removed = sweep_stale_locks("demo")

    assert removed == 0
    assert (lock_dir / "demo-1234.lock").exists()


def test_sweep_removes_dead_immediately(tmp_path, monkeypatch) -> None:
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir()
    monkeypatch.setattr("mcp_core.lifecycle.lock._lock_dir", lambda: lock_dir)
    monkeypatch.setattr("mcp_core.lifecycle.lock._is_alive", lambda meta: False)

    fresh = datetime.now(timezone.utc) - timedelta(minutes=5)
    meta = LockMetadata(
        pid=999, port=1234, token="t", spawned_at=fresh, cred_state="configured", last_activity_at=fresh
    )
    (lock_dir / "demo-1234.lock").write_text(serialize_lock(meta), encoding="utf-8")

    monkeypatch.setattr("mcp_core.lifecycle.lock._terminate_daemon", lambda pid: None)

    removed = sweep_stale_locks("demo")

    assert removed == 1
    assert not (lock_dir / "demo-1234.lock").exists()


def test_constants_set_correctly() -> None:
    assert LIFECYCLE_TTL_CONFIGURED == timedelta(hours=24)
    assert LIFECYCLE_TTL_UNCONFIGURED == timedelta(minutes=30)
