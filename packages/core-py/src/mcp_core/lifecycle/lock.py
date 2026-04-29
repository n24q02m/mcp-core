"""Cross-process lifecycle lock -- fcntl on Unix, msvcrt on Windows.

Ensures only one daemon instance runs per (name, port) tuple. Used by
auto-ensure stdio proxy spawning and by server startup to prevent races
when two agents launch the same MCP server simultaneously.

The lock file stores up to 6 lines of human-readable metadata:

::

    {pid}
    {port}
    {token}
    {spawned_at_iso8601_utc}
    {cred_state}                # "configured" | "unconfigured" (D9)
    {last_activity_at_iso8601_utc}  # bumped by daemon refresh loop (D9)

Lines 5-6 were added in D9 (Wave 1) for the hybrid TTL sweep. Locks
written by older daemons (4 lines) parse with ``cred_state="configured"``
and ``last_activity_at = spawned_at`` so backward compat is preserved.

On Windows we lock a single sentinel byte at a high offset (past the
metadata region) so readers on separate handles can still ``read_text``
the metadata while the lock is held — without that, ``msvcrt.locking`` at
offset 0 makes the whole file unreadable from other processes.

Stale lock detection (``sweep_stale_locks``) considers a lock expired when
either its writing PID is dead OR the timestamp is older than the
applicable TTL. The hybrid TTL is:

- ``cred_state == "configured"`` → 24h (long-lived configured daemon)
- ``cred_state == "unconfigured"`` → 30 min (idle setup daemon, kill fast)

Dead-PID locks are removed immediately regardless of TTL.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import TracebackType
from typing import Any, Optional

# Windows locks a single sentinel byte at this offset. Must be past any
# metadata we ever write so readers on separate handles don't collide with
# the range lock. 1 MiB is ample headroom and still cheap (sparse file).
_WIN_LOCK_OFFSET = 1 << 20

DEFAULT_LOCK_TTL_HOURS = 24

# D9 hybrid TTL constants. ``sweep_stale_locks`` selects between these based on
# the lock's ``cred_state`` field. The 30-minute window for unconfigured
# daemons exists so an idle setup daemon (browser tab closed without
# completing OAuth) is reaped quickly enough that the next stdio-proxy
# invocation re-spawns instead of bridging to a stuck daemon.
LIFECYCLE_TTL_CONFIGURED = timedelta(hours=24)
LIFECYCLE_TTL_UNCONFIGURED = timedelta(minutes=30)


@dataclass
class LockMetadata:
    """Parsed contents of a lock file.

    The canonical timestamp field is ``spawned_at``; ``created_at`` remains
    as a read-only property so existing callers (parse, refresh, format
    tests written against the 4-line schema) continue to work without
    modification. New callers should use ``spawned_at`` and consult
    ``cred_state`` / ``last_activity_at`` directly.
    """

    pid: int
    port: int
    token: str
    spawned_at: datetime
    cred_state: str = "configured"  # "configured" | "unconfigured"
    last_activity_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if self.last_activity_at is None:
            self.last_activity_at = self.spawned_at

    @property
    def created_at(self) -> datetime:
        """Backward-compat alias — pre-D9 callers read ``created_at``."""
        return self.spawned_at


def serialize_lock(meta: LockMetadata) -> str:
    """Serialize ``LockMetadata`` to the 6-line on-disk format.

    Trailing newline included so the on-disk file always ends in ``\\n``.
    Used by D9 sweep tests + future writers; the existing
    ``LifecycleLock.__enter__`` still writes the legacy 4-line payload to
    keep behavior bit-for-bit identical until Task 1.11 swaps it.
    """
    last_activity = meta.last_activity_at if meta.last_activity_at is not None else meta.spawned_at
    return (
        f"{meta.pid}\n"
        f"{meta.port}\n"
        f"{meta.token}\n"
        f"{meta.spawned_at.isoformat()}\n"
        f"{meta.cred_state}\n"
        f"{last_activity.isoformat()}\n"
    )


def parse_lock(raw: str) -> LockMetadata:
    """Parse the textual lock payload into ``LockMetadata``.

    Accepts 4-line legacy, 5-line Sentinel-#124 transitional, and 6-line
    D9 modern formats. Raises ``ValueError`` on fewer than 4 lines or
    unparseable timestamp / pid / port.
    """
    lines = raw.strip().split("\n")
    if len(lines) < 4:
        raise ValueError(f"lock file has too few lines: {len(lines)}")
    pid = int(lines[0].strip())
    port = int(lines[1].strip())
    token = lines[2].strip()
    spawned_at = datetime.fromisoformat(lines[3].strip())
    if len(lines) >= 6:
        cred_state = lines[4].strip()
        last_activity_at = datetime.fromisoformat(lines[5].strip())
    elif len(lines) == 5:
        # Sentinel #124 may have written 5-line variant; treat 5th as cred_state
        cred_state = lines[4].strip()
        last_activity_at = spawned_at
    else:
        # Legacy v1 format — assume configured + last activity = spawned
        cred_state = "configured"
        last_activity_at = spawned_at
    return LockMetadata(
        pid=pid,
        port=port,
        token=token,
        spawned_at=spawned_at,
        cred_state=cred_state,
        last_activity_at=last_activity_at,
    )


def _locks_dir(root: Path | None = None) -> Path:
    """Resolve the lock directory, honoring caller-supplied ``root`` if given.

    Existing callers pass ``root=tmp_path`` from pytest fixtures so the
    sweep can be exercised under a temp dir. New D9 tests instead
    ``monkeypatch`` ``_lock_dir`` (no-arg variant below) so this kwarg
    fallback path is rarely hit but kept for backward compat.
    """
    return root or Path.home() / ".config" / "mcp" / "locks"


def _lock_dir() -> Path:
    """No-arg variant of ``_locks_dir`` — easy monkeypatch target for D9 tests."""
    return _locks_dir(None)


def parse_lock_metadata(path: Path) -> LockMetadata | None:
    """Return parsed metadata or ``None`` for missing / unparseable / legacy
    (3-line) lock files. Legacy locks are treated as stale and cleaned on
    the next sweep.

    Note: this returns ``None`` for 3-line legacy format (preserving prior
    behavior used by ``test_lock_format`` and ``sweep_stale_locks``). For
    4/5/6-line format use ``parse_lock`` directly to get the full
    ``cred_state`` + ``last_activity_at`` fields.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        meta = parse_lock(raw)
    except ValueError:
        return None
    # parse_lock accepts 3-line input by raising ValueError, so any
    # successful parse here came from 4+ lines as required.
    return meta


def is_lock_expired(path: Path, ttl_hours: int = DEFAULT_LOCK_TTL_HOURS) -> bool:
    """Lock is expired if older than ``ttl_hours`` OR has a legacy 3-line
    format (treated as stale to migrate to 4-line on next acquire)."""
    md = parse_lock_metadata(path)
    if md is None:
        return True
    age = datetime.now(timezone.utc) - md.spawned_at
    return age.total_seconds() > ttl_hours * 3600


def _is_pid_alive(pid: int) -> bool:
    """Cross-platform PID liveness check. Best-effort; may have false positives
    when a long-running host reuses PIDs (the TTL check guards against that)."""
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            import ctypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            return False
        else:
            os.kill(pid, 0)
            return True
    except (OSError, PermissionError):
        # On POSIX, EPERM means the process exists but we can't signal it
        # (different uid). Treat as alive — sweep should not steal locks
        # owned by other users.
        return False


def _is_alive(meta: LockMetadata) -> bool:
    """Liveness check on a parsed ``LockMetadata``. Hot-replaced in D9 tests
    via ``monkeypatch.setattr("mcp_core.lifecycle.lock._is_alive", ...)``.

    Wraps ``_is_pid_alive`` so the underlying cross-platform logic stays
    in one place.
    """
    return _is_pid_alive(meta.pid)


def _terminate_daemon(pid: int) -> None:
    """Kill the lock owner. Hot-replaced in D9 tests.

    Used by the hybrid sweep when a daemon's TTL expires while the process
    is still alive (e.g. an unconfigured daemon idle for 30 min). We
    SIGKILL on POSIX and ``TerminateProcess`` on Windows because the
    daemon may be blocked in a thread holding the OAuth setup form open;
    SIGTERM would let it ignore us.
    """
    if pid <= 0:
        return
    try:
        if os.name == "nt":
            import ctypes

            PROCESS_TERMINATE = 0x0001
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if handle:
                ctypes.windll.kernel32.TerminateProcess(handle, 1)
                ctypes.windll.kernel32.CloseHandle(handle)
        else:
            import signal as _signal

            os.kill(pid, _signal.SIGKILL)
    except (OSError, PermissionError):
        pass


def refresh_lock_timestamp(path: Path) -> None:
    """Rewrite the ``spawned_at`` field of an existing 4-line lock file in
    place. Called by long-running daemons to keep their lock outside the
    TTL sweep window. No-ops silently if the file is missing / malformed
    so callers don't have to wrap in try/except.

    Preserves the on-disk line count: a 4-line legacy lock stays 4 lines
    after refresh; a 6-line modern lock stays 6 lines (with both
    ``spawned_at`` and ``last_activity_at`` bumped).
    """
    md = parse_lock_metadata(path)
    if md is None:
        return
    now = datetime.now(timezone.utc)
    # Try to detect whether the file currently uses the new 6-line schema
    # so we don't silently truncate cred_state / last_activity_at on
    # refresh. Legacy 4-line files stay 4-line.
    try:
        raw_lines = path.read_text(encoding="utf-8").strip().split("\n")
    except OSError:
        return
    if len(raw_lines) >= 6:
        payload = f"{md.pid}\n{md.port}\n{md.token}\n{now.isoformat()}\n{md.cred_state}\n{now.isoformat()}\n"
    else:
        payload = f"{md.pid}\n{md.port}\n{md.token}\n{now.isoformat()}\n"
    try:
        # Preserve fixed-width padding so the on-disk size never shrinks
        # while a Windows byte-range lock is held past the metadata region.
        with open(path, "r+", encoding="utf-8") as fh:
            fh.seek(0)
            fh.write(payload.ljust(512, " "))
            fh.flush()
    except OSError:
        # Best-effort; daemon stays alive even if refresh fails.
        return


def sweep_stale_locks(
    server_name: str,
    ttl_hours: int = DEFAULT_LOCK_TTL_HOURS,
    root: Path | None = None,
) -> int:
    """Remove stale lock files for ``server_name`` (D9 hybrid TTL).

    A lock is stale when *any* of:
    - file has legacy 3-line format / is unparseable → migrate by deletion
    - writing PID does not exist on this host (terminate not needed)
    - ``cred_state == "configured"`` and ``last_activity_at`` older than
      ``ttl_hours`` (default 24h)
    - ``cred_state == "unconfigured"`` and ``last_activity_at`` older than
      ``LIFECYCLE_TTL_UNCONFIGURED`` (30 min — fixed, not influenced by
      ``ttl_hours`` because the unconfigured TTL is a hard SLO)

    For the configured case, ``ttl_hours`` is honored for backward compat
    with pre-D9 callers; new callers should leave it at the default and
    rely on the hybrid behavior. When the lock is past TTL but the PID is
    still alive, the daemon is terminated via ``_terminate_daemon`` before
    the file is unlinked.

    Returns count of files removed. Called by ``run_local_server`` at
    daemon startup before acquiring its own lock.
    """
    if root is not None:
        locks_dir = root
    else:
        locks_dir = _lock_dir()
    if not locks_dir.exists():
        return 0

    removed = 0
    now = datetime.now(timezone.utc)
    for path in locks_dir.glob(f"{server_name}-*.lock"):
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
            continue
        try:
            meta = parse_lock(raw)
        except ValueError:
            # 3-line legacy / corrupted — migrate by deletion.
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
            continue
        if not _is_alive(meta):
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
            continue
        if meta.cred_state == "configured":
            ttl = timedelta(hours=ttl_hours)
        else:
            ttl = LIFECYCLE_TTL_UNCONFIGURED
        last_activity = meta.last_activity_at if meta.last_activity_at is not None else meta.spawned_at
        if (now - last_activity) > ttl:
            # Only terminate idle setup daemons aggressively. Configured
            # daemons past TTL (rare — the daemon's refresh loop should
            # have bumped ``last_activity_at``) get their lock unlinked
            # but the process is left alone so a long-running configured
            # daemon never gets SIGKILL'd by a sweep race. This also
            # preserves pre-D9 behavior: the legacy ``sweep_stale_locks``
            # only ever unlinked, never terminated.
            if meta.cred_state == "unconfigured":
                _terminate_daemon(meta.pid)
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
            # D17.3: clean up companion sentinel + cache files so orphan
            # .tools-list-changed / .tools.json files don't accumulate.
            for suffix in (".tools-list-changed", ".tools.json"):
                companion = path.with_suffix(suffix)
                if companion.exists():
                    try:
                        companion.unlink()
                    except OSError:
                        pass
    return removed


class LifecycleLock:
    def __init__(
        self,
        name: str,
        port: int,
        root: Path | None = None,
        token: str | None = None,
    ) -> None:
        self._name = name
        self._port = port
        self._token = token
        self._root = _locks_dir(root)
        self._root.mkdir(parents=True, exist_ok=True)
        if sys.platform != "win32":
            self._root.chmod(0o700)
        self._lock_file = self._root / f"{name}-{port}.lock"
        self._fh: Any | None = None

    @property
    def path(self) -> Path:
        """Location of the lock file on disk."""
        return self._lock_file

    def __enter__(self) -> "LifecycleLock":
        # Open in read+write without truncation so concurrent openers never
        # race on truncate. We explicitly truncate *after* acquiring the lock.
        try:
            self._fh = open(self._lock_file, "a+", encoding="utf-8")
        except OSError as e:
            raise RuntimeError(f"Failed to open lock file: {e}") from e
        if sys.platform == "win32":
            import msvcrt

            try:
                self._fh.seek(_WIN_LOCK_OFFSET)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as e:
                self._fh.close()
                self._fh = None
                raise RuntimeError(f"LifecycleLock: another process holds {self._lock_file}") from e
        else:
            import fcntl

            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as e:
                self._fh.close()
                self._fh = None
                raise RuntimeError(f"LifecycleLock: another process holds {self._lock_file}") from e
        # Rewrite metadata from offset 0. We cannot ``truncate(0)`` on
        # Windows without dropping our byte-range lock, so we write a
        # fixed-size record and pad with spaces so any stale tail is
        # overwritten deterministically. We continue to write the legacy
        # 4-line payload here for backward compat — the D9 hybrid sweep
        # treats 4-line as ``cred_state="configured"`` so behavior is
        # equivalent for daemons that don't yet opt into 6-line writes.
        self._fh.seek(0)
        created_at = datetime.now(timezone.utc).isoformat()
        payload = f"{os.getpid()}\n{self._port}\n{self._token or ''}\n{created_at}\n"
        self._fh.write(payload.ljust(512, " "))
        self._fh.flush()
        if sys.platform != "win32":
            os.chmod(self._lock_file, 0o600)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._fh is not None:
            if sys.platform == "win32":
                import msvcrt

                try:
                    self._fh.seek(_WIN_LOCK_OFFSET)
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            self._fh.close()
            self._fh = None
            try:
                self._lock_file.unlink(missing_ok=True)
            except OSError:
                pass
