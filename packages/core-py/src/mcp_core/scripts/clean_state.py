"""mcp-clean-state CLI — D14.

Removes MCP server credentials (legacy config.enc + PerPluginStore config.json /
.secret / subs tree), locks, tools cache, and per-server token caches. By
default preserves app data (SQLite, diskcache, SearXNG state).

The ``--kill-daemons`` flag terminates any alive legacy bridge daemons before
removing their lock files. Required after upgrading from mcp-core <=1.11.x to
2.0.0+ where the stdio bridge / smart-stdio layer was removed in favor of
direct FastMCP stdio mode and pure HTTP servers. See
``docs/migration-2026-04-30.md``.

BREAKING: non-interactive callers (no tty) must now pass ``--yes`` explicitly
to confirm deletion. Previously a missing tty auto-confirmed, so any
non-interactive wrapper silently deleted credentials.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from pathlib import Path

from platformdirs import user_config_dir

ALL_SERVERS = [
    "wet-mcp",
    "mnemo-mcp",
    "better-code-review-graph",
    "imagine-mcp",
    "better-notion-mcp",
    "better-email-mcp",
    "better-telegram-mcp",
    "better-godot-mcp",
    "better-workspace-mcp",
]


def _home() -> Path:
    return Path.home()


def _python_config_base() -> Path:
    """Where Python core-py writes config.enc — platformdirs convention.

    Linux: ``~/.config/mcp``. macOS: ``~/Library/Application Support/mcp``.
    Windows: ``%LOCALAPPDATA%\\mcp``.
    """
    return Path(user_config_dir("mcp", appauthor=False))


def _ts_config_base() -> Path | None:
    """Where TS core-ts writes config.enc on Windows — Node electron convention.

    On Windows: ``%APPDATA%\\mcp\\Config``. On POSIX, TS uses the same
    ``~/.config/mcp`` dir as Python so we return None to avoid duplicate
    enumeration.
    """
    if os.name != "nt":
        return None
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return None
    return Path(appdata) / "mcp" / "Config"


def _legacy_posix_base() -> Path:
    """Locks + tools cache are still hardcoded to ``~/.config/mcp/`` in
    ``mcp_core.lifecycle.lock`` + ``mcp_core.transport.cache`` regardless
    of platform (Linux convention even on Windows). Tracked separately
    here so we keep covering them until those modules migrate to
    platformdirs.
    """
    return _home() / ".config" / "mcp"


def _config_paths() -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()

    def _add(p: Path) -> None:
        try:
            key = p.resolve()
        except OSError:
            key = p
        if key in seen:
            return
        seen.add(key)
        paths.append(p)

    # Python core-py + TS core-ts config.enc — platform-specific.
    for base in (_python_config_base(), _ts_config_base(), _legacy_posix_base()):
        if base is None:
            continue
        cfg = base / "config.enc"
        if cfg.exists():
            _add(cfg)

    # Locks + tools cache still live under the legacy ~/.config/mcp/ tree.
    legacy = _legacy_posix_base()
    locks = legacy / "locks"
    if locks.exists():
        for p in locks.glob("*.lock"):
            _add(p)
    cache = legacy / "cache"
    if cache.exists():
        for p in cache.glob("*.tools.json"):
            _add(p)
    return paths


def _per_plugin_store_paths(server: str) -> list[Path]:
    """Credential paths written by ``mcp_core.storage.per_plugin_store.PerPluginStore``
    via its ``LocalFsBackend`` (see ``storage/backends.py::_key_to_path`` for the
    authoritative on-disk layout), under ``~/.<server>/``:

    - ``config.json`` — single-user (stdio / HTTP single-user) credential blob.
    - ``.secret`` — machine-bound AES-GCM key for the single-user mode above.
    - ``subs/<sub>/config.json`` and ``subs/<sub>/tokens/<provider>.json`` —
      HTTP multi-user mode, one directory per OAuth ``sub``. The whole ``subs``
      tree is enumerated so nested per-sub token files are covered too.

    None of these were covered by the legacy ``config.enc`` wipe, so every
    "clean state" E2E run since the PerPluginStore migration reused whatever
    credentials were already on disk.
    """
    base = _home() / f".{server}"
    if not base.exists():
        return []
    out: list[Path] = []
    cfg = base / "config.json"
    if cfg.exists():
        out.append(cfg)
    secret = base / ".secret"
    if secret.exists():
        out.append(secret)
    subs = base / "subs"
    if subs.exists():
        out.append(subs)
    return out


def _per_server_token_paths(server: str) -> list[Path]:
    base = _home() / f".{server}"
    if not base.exists():
        return []
    out: list[Path] = []
    tokens = base / "tokens"
    if tokens.exists():
        out.extend(tokens.glob("*"))
    sessions = base / "sessions"
    if sessions.exists():
        out.extend(sessions.glob("*.session"))
    cache = base / "cache"
    if cache.exists() and server == "imagine-mcp":
        out.extend(cache.glob("*"))
    return out


def _per_server_data_paths(server: str) -> list[Path]:
    base = _home() / f".{server}"
    if not base.exists():
        return []
    out: list[Path] = []
    data = base / "data"
    if data.exists():
        out.append(data)
    if server == "imagine-mcp":
        diskcache = base / "diskcache"
        if diskcache.exists():
            out.append(diskcache)
    return out


def _enumerate(servers: list[str], keep_data: bool) -> list[Path]:
    paths = list(_config_paths())
    for srv in servers:
        paths.extend(_per_plugin_store_paths(srv))
        paths.extend(_per_server_token_paths(srv))
        if not keep_data:
            paths.extend(_per_server_data_paths(srv))
    return paths


def _confirm(assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("refusing: pass --yes for non-interactive", file=sys.stderr)
        return False
    print("Proceed? [y/N] ", end="", flush=True)
    line = sys.stdin.readline().strip().lower()
    return line in ("y", "yes")


def _lock_dir() -> Path:
    """Lock files directory — same legacy location used by lifecycle.lock."""
    return _legacy_posix_base() / "locks"


def _parse_lock_pid(lock_path: Path) -> int | None:
    """Parse PID from a lock file. Returns None on malformed or missing file.

    Lock format (per ``lifecycle.lock.LockMetadata``)::

        line 0: {pid}
        line 1: {port}
        line 2: {token}
        line 3: {spawned_at_iso8601_utc}
        line 4: {cred_state}             # optional (D9+)
        line 5: {last_activity_at}       # optional (D9+)
    """
    try:
        text = lock_path.read_text()
    except OSError:
        return None
    lines = text.splitlines()
    if not lines:
        return None
    try:
        pid = int(lines[0].strip())
    except (ValueError, IndexError):
        return None
    if pid <= 0:
        return None
    return pid


def _is_pid_alive(pid: int) -> bool:
    """Cross-platform PID liveness check used by the legacy ``kill_daemons``
    migration helper. Best-effort; may have false positives when a long-running
    host reuses PIDs (the lock TTL guards against that)."""
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
        return False


def _terminate_daemon(pid: int) -> None:
    """Kill a legacy daemon process. Used only by ``kill_daemons`` migration
    helper for users upgrading from mcp-core <=1.11.x."""
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


def kill_daemons(verbose: bool = False) -> tuple[int, int]:
    """Terminate alive MCP daemons and remove their lock + companion files.

    For each ``*.lock`` file under ``~/.config/mcp/locks/``:

    1. Parse PID from line 0.
    2. If PID alive, terminate it (SIGKILL on POSIX, TerminateProcess on Windows)
       via the local ``_terminate_daemon`` helper (cross-platform).
    3. Remove the lock file.
    4. Remove companion ``<lock-stem>*.tools.json`` cache file under
       ``~/.config/mcp/cache/`` if present.
    5. Remove sibling ``<lock>.tools-list-changed`` sentinel if present.

    Returns ``(killed_count, removed_lock_count)``. Missing lock dir returns
    ``(0, 0)`` after a no-op message.
    """
    lock_dir = _lock_dir()
    if not lock_dir.exists():
        print("No lock directory; nothing to clean.")
        return (0, 0)

    locks = sorted(lock_dir.glob("*.lock"))
    if not locks:
        print("No lock files; nothing to clean.")
        return (0, 0)

    cache_dir = _legacy_posix_base() / "cache"

    killed = 0
    removed = 0
    for lock in locks:
        pid = _parse_lock_pid(lock)
        if pid is not None and _is_pid_alive(pid):
            _terminate_daemon(pid)
            # Brief pause to let the OS reap the process so subsequent lock
            # writes by mcp-core do not collide with the old PID's handle.
            for _ in range(20):
                if not _is_pid_alive(pid):
                    break
                time.sleep(0.05)
            killed += 1
            if verbose:
                print(f"killed: pid={pid} ({lock.name})")

        try:
            lock.unlink()
            removed += 1
            if verbose:
                print(f"removed: {lock}")
        except OSError as exc:
            print(f"failed to remove {lock}: {exc}", file=sys.stderr)

        # Companion tools cache lives at:
        #   ~/.config/mcp/cache/<server>-<pid>-<protocol>-<core>.tools.json
        # We match by server+pid prefix since protocol/core suffix varies.
        if cache_dir.exists() and pid is not None:
            stem_prefix = f"{lock.stem}-"  # e.g. "wet-mcp-1234-"
            for cache_file in cache_dir.glob(f"{stem_prefix}*.tools.json"):
                try:
                    cache_file.unlink()
                    if verbose:
                        print(f"removed: {cache_file}")
                except OSError as exc:
                    print(f"failed to remove {cache_file}: {exc}", file=sys.stderr)

        # Sibling sentinel ``<lock>.tools-list-changed`` (if used by future code).
        sentinel = lock.with_suffix(lock.suffix + ".tools-list-changed")
        if sentinel.exists():
            try:
                sentinel.unlink()
                if verbose:
                    print(f"removed: {sentinel}")
            except OSError as exc:
                print(f"failed to remove {sentinel}: {exc}", file=sys.stderr)

    print(f"Killed {killed} daemons; cleaned {removed} lock files.")
    return (killed, removed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-clean-state",
        description="Clear MCP server credentials, locks, and tools cache.",
    )
    parser.add_argument(
        "--keep-data",
        dest="keep_data",
        action="store_true",
        default=True,
        help="Preserve app data (SQLite, diskcache, SearXNG, GDrive cached docs). Default: ON.",
    )
    parser.add_argument("--no-keep-data", dest="keep_data", action="store_false", help="Wipe app data dirs too.")
    parser.add_argument("--server", default=None, help="Limit to one server name. Default: all 9.")
    parser.add_argument("--dry-run", action="store_true", help="List paths that would be removed.")
    parser.add_argument("--verbose", action="store_true", help="Print each removed path.")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt (required for non-interactive use).",
    )
    parser.add_argument(
        "--kill-daemons",
        action="store_true",
        help=(
            "Terminate alive MCP daemons and remove their lock + tools cache + sentinel files. "
            "Required after upgrading from mcp-core <=1.11.x to 1.12.0+ "
            "(see docs/migration-2026-04-30.md). Runs before any other cleanup."
        ),
    )
    args = parser.parse_args(argv)

    if args.kill_daemons:
        if not _confirm(args.yes):
            return 1
        kill_daemons(verbose=args.verbose)
        return 0

    servers = [args.server] if args.server else list(ALL_SERVERS)
    if args.server and args.server not in ALL_SERVERS:
        print(f"unknown server: {args.server}; allowed: {ALL_SERVERS}", file=sys.stderr)
        return 2

    paths = _enumerate(servers, args.keep_data)

    if not paths:
        print("Nothing to clean.")
        return 0

    print(f"{'[dry-run] Would remove' if args.dry_run else 'Will remove'} {len(paths)} path(s):")
    for p in paths:
        print(f"  {p}")

    if args.dry_run:
        return 0

    if not _confirm(args.yes):
        print("Aborted.")
        return 1

    removed = 0
    for p in paths:
        try:
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            if args.verbose:
                print(f"removed: {p}")
            removed += 1
        except OSError as exc:
            print(f"failed: {p} ({exc})", file=sys.stderr)

    print(f"Removed {removed}/{len(paths)} path(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
