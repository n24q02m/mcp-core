"""Cross-process lifecycle lock -- fcntl on Unix, msvcrt on Windows.

Ensures only one daemon instance runs per (name, port) tuple. Used by
auto-ensure stdio proxy spawning and by server startup to prevent races
when two agents launch the same MCP server simultaneously.

The lock file stores ``{pid}\\n{port}\\n`` as human-readable metadata so
operators can inspect who holds the lock. On Windows we lock a single
sentinel byte at a high offset (past the metadata region) so readers on
separate handles can still ``read_text`` the metadata while the lock is
held - without that, ``msvcrt.locking`` at offset 0 makes the whole file
unreadable from other processes.
"""

import os
import sys
from pathlib import Path
from types import TracebackType
from typing import Any

# Windows locks a single sentinel byte at this offset. Must be past any
# metadata we ever write so readers on separate handles don't collide with
# the range lock. 1 MiB is ample headroom and still cheap (sparse file).
_WIN_LOCK_OFFSET = 1 << 20


class LifecycleLock:
    def __init__(self, name: str, port: int, root: Path | None = None, token: str | None = None) -> None:
        self._name = name
        self._port = port
        self._token = token
        self._root = root or Path.home() / ".config" / "mcp" / "locks"
        self._root.mkdir(parents=True, exist_ok=True)
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
        # overwritten deterministically.
        self._fh.seek(0)
        payload = f"{os.getpid()}\n{self._port}\n{self._token or ''}\n"
        self._fh.write(payload.ljust(512, " "))
        self._fh.flush()
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
