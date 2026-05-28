#!/usr/bin/env python3
"""Audit invariant: at most 1 HTTP daemon process per plugin name.

Stdio-direct mode = no daemon. HTTP mode = single daemon. >1 = race
condition or stale-lock-not-swept-before-acquire bug.

Run via: uv run python scripts/audit/multi_daemon_invariant.py

Exit codes:
    0 = OK (no plugin has >1 HTTP daemon)
    1 = violation (one or more plugins have >=2 HTTP daemons)
    2 = setup error (psutil missing)
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict

try:
    import psutil
except ImportError:
    print("psutil not installed; install: pip install psutil", file=sys.stderr)
    sys.exit(2)

DEFAULT_PLUGINS = (
    "wet-mcp",
    "mnemo-mcp",
    "better-code-review-graph",
    "imagine-mcp",
    "better-telegram-mcp",
    "better-notion-mcp",
    "better-email-mcp",
    "better-godot-mcp",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit multi-daemon invariant")
    parser.add_argument(
        "plugins",
        nargs="*",
        default=DEFAULT_PLUGINS,
        help="Plugins to audit (default: all known plugins)",
    )
    args = parser.parse_args()

    counts: dict[str, int] = defaultdict(int)
    for proc in psutil.process_iter(["name", "cmdline", "environ"]):
        try:
            cmdline_list = proc.info.get("cmdline") or []
            cmd = " ".join(cmdline_list)
            environ = proc.info.get("environ") or {}

            for plugin in args.plugins:
                if plugin not in cmd:
                    continue
                # Match HTTP daemon by transport flag (env or arg). Substring
                # check on joined cmd catches both inlined env (`MCP_TRANSPORT=http
                # uvx ...`) and standalone token forms; --http catches CLI flag.
                # Also check proc.environ directly for robust detection.
                is_http = (
                    "MCP_TRANSPORT=http" in cmd
                    or "--http" in cmdline_list
                    or environ.get("MCP_TRANSPORT") == "http"
                )
                if is_http:
                    counts[plugin] += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    violations = {p: c for p, c in counts.items() if c > 1}
    if violations:
        print("FAIL: multi-daemon invariant violation:")
        for plugin, count in sorted(violations.items()):
            print(f"  {plugin}: {count} HTTP daemons")
        return 1

    print(f"OK: at most 1 HTTP daemon per plugin (audited {len(args.plugins)} plugins)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
