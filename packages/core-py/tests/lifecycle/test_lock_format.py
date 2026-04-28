"""Tests for the 4-line lock file format + parse / expiry helpers."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from mcp_core.lifecycle.lock import (
    DEFAULT_LOCK_TTL_HOURS,
    LifecycleLock,
    is_lock_expired,
    parse_lock_metadata,
    refresh_lock_timestamp,
)


def _write_legacy_lock(path: Path, pid: int, port: int) -> None:
    path.write_text(f"{pid}\n{port}\nproxy-token\n", encoding="utf-8")


def _write_4line_lock(path: Path, pid: int, port: int, age_hours: float = 0) -> None:
    ts = (datetime.now(timezone.utc) - timedelta(hours=age_hours)).isoformat()
    path.write_text(f"{pid}\n{port}\nproxy-token\n{ts}\n", encoding="utf-8")


def test_lifecycle_lock_writes_4_line_payload(tmp_path):
    with LifecycleLock("demo", 12345, root=tmp_path, token="t"):
        path = tmp_path / "demo-12345.lock"
        lines = path.read_text(encoding="utf-8").rstrip().split("\n")
        assert len(lines) == 4
        assert lines[0].strip() == str(__import__("os").getpid())
        assert lines[1].strip() == "12345"
        assert lines[2].strip() == "t"
        # Line 4 = parseable ISO 8601 with timezone.
        ts = datetime.fromisoformat(lines[3].strip())
        assert ts.tzinfo is not None


def test_parse_lock_metadata_returns_all_fields(tmp_path):
    path = tmp_path / "demo-12345.lock"
    _write_4line_lock(path, 9999, 12345)
    md = parse_lock_metadata(path)
    assert md is not None
    assert md.pid == 9999
    assert md.port == 12345
    assert md.token == "proxy-token"
    assert md.created_at.tzinfo is not None


def test_parse_lock_metadata_rejects_legacy_3_line_format(tmp_path):
    path = tmp_path / "demo-12345.lock"
    _write_legacy_lock(path, 9999, 12345)
    assert parse_lock_metadata(path) is None


def test_parse_lock_metadata_returns_none_for_missing_file(tmp_path):
    assert parse_lock_metadata(tmp_path / "missing.lock") is None


def test_parse_lock_metadata_returns_none_for_corrupted_pid(tmp_path):
    path = tmp_path / "demo.lock"
    path.write_text("not_an_int\n12345\nt\n2026-01-01T00:00:00+00:00\n", encoding="utf-8")
    assert parse_lock_metadata(path) is None


def test_is_lock_expired_after_24h(tmp_path):
    path = tmp_path / "demo.lock"
    _write_4line_lock(path, 9999, 12345, age_hours=25)
    assert is_lock_expired(path, ttl_hours=24) is True


def test_is_lock_not_expired_within_ttl(tmp_path):
    path = tmp_path / "demo.lock"
    _write_4line_lock(path, 9999, 12345, age_hours=23)
    assert is_lock_expired(path, ttl_hours=24) is False


def test_is_lock_expired_for_legacy_format(tmp_path):
    path = tmp_path / "demo.lock"
    _write_legacy_lock(path, 9999, 12345)
    assert is_lock_expired(path) is True


def test_default_lock_ttl_is_24h():
    assert DEFAULT_LOCK_TTL_HOURS == 24


def test_refresh_lock_timestamp_updates_4th_line(tmp_path):
    path = tmp_path / "demo.lock"
    _write_4line_lock(path, 9999, 12345, age_hours=10)
    md_before = parse_lock_metadata(path)
    assert md_before is not None
    refresh_lock_timestamp(path)
    md_after = parse_lock_metadata(path)
    assert md_after is not None
    assert md_after.created_at > md_before.created_at
    # Other fields preserved.
    assert md_after.pid == md_before.pid
    assert md_after.port == md_before.port
    assert md_after.token == md_before.token


def test_refresh_lock_timestamp_silent_on_legacy_lock(tmp_path):
    path = tmp_path / "demo.lock"
    _write_legacy_lock(path, 9999, 12345)
    refresh_lock_timestamp(path)  # must not raise
    # File untouched (still legacy 3-line — no metadata to refresh).
    assert parse_lock_metadata(path) is None
