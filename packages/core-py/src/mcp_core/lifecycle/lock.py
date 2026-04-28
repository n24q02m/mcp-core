"""Cross-process lifecycle lock -- fcntl on Unix, msvcrt on Windows.

Ensures only one daemon instance runs per (name, port) tuple. Used by
auto-ensure stdio proxy spawning and by server startup to prevent races
when two agents launch the same MCP server simultaneously.

The lock file stores 4 lines of human-readable metadata:

::

    {pid}
    {port}
    {token}
    {created_at_iso8601_utc}

so operators can inspect who holds the lock and when it was first written.
On Windows we lock a single sentinel byte at a high offset (past the
metadata region) so readers on separate handles can still ``read_text``
the metadata while the lock is held — without that, ``msvcrt.locking`` at
offset 0 makes the whole file unreadable from other processes.

Stale lock detection (``sweep_stale_locks``) considers a lock expired when
either its writing PID is dead OR the timestamp is older than the TTL
(default 24 hours). The TTL guards against PID-reuse on long-lived hosts
where an unrelated process happens to occupy the dead daemon's PID.
"""

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Any

# Windows locks a single sentinel byte at this offset. Must be past any
# metadata we ever write so readers on separate handles don't collide with
# the range lock. 1 MiB is ample headroom and still cheap (sparse file).
_WIN_LOCK_OFFSET = 1 << 20

DEFAULT_LOCK_TTL_HOURS = 24


@dataclass(frozen=True)
class LockMetadata:
    """Parsed contents of a 4-line lock file."""

    pid: int
    port: int
    token: str
    created_at: datetime


def _locks_dir(root: Path | None = None) -> Path:
    return root or Path.home() / ".config" / "mcp" / "locks"


def parse_lock_metadata(path: Path) -> LockMetadata | None:
    """Return parsed metadata or ``None`` for missing / unparseable / legacy
    (3-line) lock files. Legacy locks are treated as stale and cleaned on
    the next sweep.
    """
    try:
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        if len(lines) < 4:
            return None
        return LockMetadata(
            pid=int(lines[0].strip()),
            port=int(lines[1].strip()),
            token=lines[2].strip(),
            created_at=datetime.fromisoformat(lines[3].strip()),
        )
    except (OSError, ValueError):
        return None


def is_lock_expired(path: Path, ttl_hours: int = DEFAULT_LOCK_TTL_HOURS) -> bool:
    """Lock is expired if older than ``ttl_hours`` OR has a legacy 3-line
    format (treated as stale to migrate to 4-line on next acquire)."""
    md = parse_lock_metadata(path)
    if md is None:
        return True
    age = datetime.now(timezone.utc) - md.created_at
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
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
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


def refresh_lock_timestamp(path: Path) -> None:
    """Rewrite the ``created_at`` field of an existing 4-line lock file in
    place. Called by long-running daemons to keep their lock outside the
    TTL sweep window. No-ops silently if the file is missing / malformed
    so callers don't have to wrap in try/except."""
    md = parse_lock_metadata(path)
    if md is None:
        return
    payload = (
        f"{md.pid}\n{md.port}\n{md.token}\n"
        f"{datetime.now(timezone.utc).isoformat()}\n"
    )
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
    """Remove stale lock files for ``server_name``.

    A lock is stale when *any* of:
    - file has legacy 3-line format (no timestamp) → migrate by deletion
    - timestamp older than ``ttl_hours``
    - writing PID does not exist on this host

    Returns count of files removed. Called by ``run_local_server`` at
    daemon startup before acquiring its own lock.
    """
    locks_dir = _locks_dir(root)
    if not locks_dir.exists():
        return 0

    removed = 0
    for path in locks_dir.glob(f"{server_name}-*.lock"):
        md = parse_lock_metadata(path)
        if md is None:
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
            continue
        if is_lock_expired(path, ttl_hours) or not _is_pid_alive(md.pid):
            try:
                path.unlink()
                removed += 1
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
                raise RuntimeError(
                    f"LifecycleLock: another process holds {self._lock_file}"
                ) from e
        else:
            import fcntl

            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as e:
                self._fh.close()
                self._fh = None
                raise RuntimeError(
                    f"LifecycleLock: another process holds {self._lock_file}"
                ) from e
        # Rewrite metadata from offset 0. We cannot ``truncate(0)`` on
        # Windows without dropping our byte-range lock, so we write a
        # fixed-size record and pad with spaces so any stale tail is
        # overwritten deterministically.
        self._fh.seek(0)
        created_at = datetime.now(timezone.utc).isoformat()
        payload = (
            f"{os.getpid()}\n{self._port}\n{self._token or ''}\n{created_at}\n"
        )
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
