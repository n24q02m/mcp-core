"""Cross-process lifecycle lock -- fcntl on Unix, msvcrt on Windows.

Ensures only one daemon instance runs per (name, port) tuple. Used by
auto-ensure stdio proxy spawning and by server startup to prevent races
when two agents launch the same MCP server simultaneously.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from types import TracebackType
from typing import Any


class LifecycleLock:
    def __init__(self, name: str, port: int, root: Path | None = None) -> None:
        self._name = name
        self._port = port
        self._root = root or Path.home() / ".config" / "mcp" / "locks"
        self._root.mkdir(parents=True, exist_ok=True)
        self._lock_file = self._root / f"{name}-{port}.lock"
        self._fh: Any | None = None

    def __enter__(self) -> "LifecycleLock":
        self._fh = open(self._lock_file, "w", encoding="utf-8")
        if sys.platform == "win32":
            import msvcrt

            try:
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
        self._fh.write(f"{os.getpid()}\n")
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
