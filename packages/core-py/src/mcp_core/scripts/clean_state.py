"""mcp-clean-state CLI — D14.

Removes MCP server credentials, locks, tools cache, and per-server token caches.
By default preserves app data (SQLite, diskcache, SearXNG state).
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
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
        paths.extend(_per_server_token_paths(srv))
        if not keep_data:
            paths.extend(_per_server_data_paths(srv))
    return paths


def _confirm() -> bool:
    if not sys.stdin.isatty():
        # Non-interactive — auto-yes
        return True
    print("Proceed? [y/N] ", end="", flush=True)
    line = sys.stdin.readline().strip().lower()
    return line in ("y", "yes")


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
    parser.add_argument("--server", default=None, help="Limit to one server name. Default: all 8.")
    parser.add_argument("--dry-run", action="store_true", help="List paths that would be removed.")
    parser.add_argument("--verbose", action="store_true", help="Print each removed path.")
    args = parser.parse_args(argv)

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

    if not _confirm():
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
