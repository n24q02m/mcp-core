"""mcp-clean-state CLI — D14.

Removes MCP server credentials, locks, tools cache, and per-server token caches.
By default preserves app data (SQLite, diskcache, SearXNG state).
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

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


def _config_paths() -> list[Path]:
    base = _home() / ".config" / "mcp"
    paths = []
    if (base / "config.enc").exists():
        paths.append(base / "config.enc")
    locks = base / "locks"
    if locks.exists():
        paths.extend(locks.glob("*.lock"))
    cache = base / "cache"
    if cache.exists():
        paths.extend(cache.glob("*.tools.json"))
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
