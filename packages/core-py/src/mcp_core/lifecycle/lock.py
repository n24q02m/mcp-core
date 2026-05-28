"""Cross-process lifecycle lock for HTTP server mode.

After the stdio-pure + http-multi-user split, lock files are used solely by
`run_http_server` / `StreamableHTTPServer` to prevent two HTTP servers
binding the same port for the same `server_name`. They are no longer used
to discover or steer daemon-bridge processes; per-cred-state TTLs and PID
liveness checks have been removed along with the daemon model.

The lock file stores 4 lines of human-readable metadata (padded to 512 bytes)::

    {pid}
    {port}
    {token}
    {spawned_at_iso8601_utc}

On Windows we lock a single sentinel byte at a high offset (past the
metadata region) so readers on separate handles can still `read_text`
the metadata while the lock is held — without that, `msvcrt.locking` at
offset 0 makes the whole file unreadable from other processes.

`sweep_stale_locks` removes lock files whose `spawned_at` is older than
the configured TTL or whose payload is unparseable. There is no daemon to
terminate -- the HTTP server owns its own lifecycle and exits when its
parent process exits.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import TracebackType
from typing import Any

# Windows locks a single sentinel byte at this offset. Must be past any
# metadata we ever write so readers on separate handles don't collide with
# the range lock. 1 MiB is ample headroom and still cheap (sparse file).
_WIN_LOCK_OFFSET = 1 << 20

DEFAULT_LOCK_TTL_HOURS = 24


@dataclass
class LockMetadata:
    """Parsed contents of a lock file."""

    pid: int
    port: int
    token: str
    spawned_at: datetime


def _parse_lock_text(raw: str) -> LockMetadata | None:
    """Parse the textual lock payload into `LockMetadata` or `None`.

    Accepts both 4-line (current) and longer (legacy 5/6-line) payloads --
    extra lines are ignored. Returns `None` for malformed files so callers
    can treat them as stale and reclaim by deletion.
    """
    lines = raw.strip().split("\n")
    if len(lines) < 4:
        return None
    try:
        pid = int(lines[0].strip())
        port = int(lines[1].strip())
    except ValueError:
        return None
    token = lines[2].strip()
    try:
        spawned_at = datetime.fromisoformat(lines[3].strip())
    except ValueError:
        return None
    return LockMetadata(pid=pid, port=port, token=token, spawned_at=spawned_at)


def _locks_dir(root: Path | None = None) -> Path:
    """Resolve the lock directory, honoring caller-supplied `root` if given.

    Existing callers pass `root=tmp_path` from pytest fixtures so the
    sweep can be exercised under a temp dir.
    """
    return root or Path.home() / ".config" / "mcp" / "locks"


def _lock_dir() -> Path:
    """No-arg variant of `_locks_dir` — easy monkeypatch target for tests."""
    return _locks_dir(None)


def refresh_lock_timestamp(path: Path) -> None:
    """Rewrite the `spawned_at` field of an existing lock file in place.

    Called by long-running HTTP servers to keep their lock outside the TTL
    sweep window. No-ops silently if the file is missing / malformed so
    callers don't have to wrap in try/except.
    """
    try:
        # Padded to 512 bytes so on-disk size stays stable while a Windows
        # byte-range lock is held past the metadata region.
        with open(path, "r+", encoding="utf-8") as fh:
            raw = fh.read(512)
            md = _parse_lock_text(raw)
            if md is None:
                return
            now = datetime.now(timezone.utc)
            payload = f"{md.pid}\n{md.port}\n{md.token}\n{now.isoformat()}\n"
            fh.seek(0)
            fh.write(payload.ljust(512, " "))
            fh.flush()
    except OSError:
        # Best-effort; server stays alive even if refresh fails.
        return


def sweep_stale_locks(
    server_name: str,
    ttl_hours: int = DEFAULT_LOCK_TTL_HOURS,
    root: Path | None = None,
) -> int:
    """Remove stale lock files for `server_name`. Returns count removed.

    A lock is stale when:
    - file is unreadable / has malformed payload (legacy / corrupt) -> remove
    - `spawned_at` older than `ttl_hours` -> remove

    We attempt to acquire an exclusive lock before unlinking. If we can lock
    it, it means no other process is holding it, and it's safe to sweep.
    """
    if root is not None:
        locks_dir = root
    else:
        locks_dir = _lock_dir()
    if not locks_dir.exists():
        return 0

    removed = 0
    now = datetime.now(timezone.utc)
    ttl = timedelta(hours=ttl_hours)
    for path in locks_dir.glob(f"{server_name}.lock"):
        try:
            with open(path, "a+", encoding="utf-8") as fh:
                # Try to acquire lock. If it fails, another process owns it.
                if sys.platform == "win32":
                    import msvcrt

                    try:
                        fh.seek(_WIN_LOCK_OFFSET)
                        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    except OSError:
                        continue
                else:
                    import fcntl

                    try:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        continue

                # Lock acquired. Check if it's stale.
                fh.seek(0)
                raw = fh.read(512)
                meta = _parse_lock_text(raw)

                is_stale = False
                if meta is None:
                    is_stale = True
                elif (now - meta.spawned_at) > ttl:
                    is_stale = True

                if is_stale:
                    try:
                        path.unlink()
                        removed += 1
                    except OSError:
                        pass

                # Unlock
                if sys.platform == "win32":
                    import msvcrt

                    try:
                        fh.seek(_WIN_LOCK_OFFSET)
                        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                else:
                    import fcntl

                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            continue

    return removed


class LifecycleLock:
    """Cross-process lock guarding a single `server_name` HTTP server.

    Acquired by `run_http_server` before binding the port so two
    instances cannot run for the same `server_name` simultaneously.
    Releases on context exit; the lock file is unlinked at that point as well.
    """

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
        self._lock_file = self._root / f"{name}.lock"
        self._fh: Any | None = None

    @property
    def path(self) -> Path:
        """Location of the lock file on disk."""
        return self._lock_file

    def __enter__(self) -> "LifecycleLock":
        # Robust "lock + verify" pattern to handle race with unlink.
        attempts = 0
        while True:
            attempts += 1
            try:
                # Open in read+write without truncation.
                self._fh = open(self._lock_file, "a+", encoding="utf-8")

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

                # Verification: ensure the file we locked still exists and is the
                # same inode as the one on disk.
                try:
                    fstat = os.fstat(self._fh.fileno())
                    dstat = os.stat(self._lock_file)
                    if fstat.st_ino != dstat.st_ino:
                        # Raced with unlink + recreate. Try again.
                        self._exit_lock()
                        if attempts >= 3:
                            raise RuntimeError("Failed to verify lock file after 3 attempts (inode mismatch)")
                        continue
                except OSError:
                    # Raced with unlink. Try again.
                    self._exit_lock()
                    if attempts >= 3:
                        raise RuntimeError("Failed to verify lock file after 3 attempts (file unlinked)")
                    continue

                # Success.
                break
            except OSError as e:
                if self._fh:
                    self._fh.close()
                    self._fh = None
                if attempts >= 3:
                    raise RuntimeError(f"Failed to open lock file after 3 attempts: {e}") from e

        # Rewrite metadata from offset 0.
        self._fh.seek(0)
        spawned_at = datetime.now(timezone.utc).isoformat()
        payload = f"{os.getpid()}\n{self._port}\n{self._token or ''}\n{spawned_at}\n"
        self._fh.write(payload.ljust(512, " "))
        self._fh.flush()
        if sys.platform != "win32":
            os.chmod(self._lock_file, 0o600)
        return self

    def _exit_lock(self) -> None:
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

                try:
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            self._fh.close()
            self._fh = None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._fh is not None:
            # Unlink first while holding the lock.
            try:
                # Only unlink if it is still the same file we locked.
                fstat = os.fstat(self._fh.fileno())
                dstat = os.stat(self._lock_file)
                if fstat.st_ino == dstat.st_ino:
                    self._lock_file.unlink(missing_ok=True)
            except OSError:
                pass
            self._exit_lock()
