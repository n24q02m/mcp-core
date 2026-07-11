"""Console-script CLI builder shared by every Python MCP server.

``build_cli`` wraps a server's existing ``serve(argv) -> int | None`` entry
point with subcommand dispatch, without changing that entry point's
behaviour for the two invocation shapes it already handles:

- Bare invocation (``argv`` empty) still means "start the server".
- Any flag-prefixed argv (``--http`` etc.) is passed through to ``serve``
  byte-for-byte, so existing ``--http`` semantics are untouched.

A leading *positional* argv[0] is treated as a subcommand name — either one
of the reserved built-ins (``config``/``relay``/``doctor``) or a
server-specific one supplied via ``extra`` — and is routed through argparse
instead of ``serve``. STDOUT is the MCP protocol channel in stdio mode, so
only this subcommand path may print to stdout; the ``serve`` path never
touches stdout and this module does not add logging to it (wet/mnemo already
own their logging setup there). ``ensure_stderr_logging`` therefore runs on
the subcommand path only, right before dispatch.

Built-in output convention: informational results (configured/not
configured, session details, doctor's ``[ok]``/``[warn]``/``[fail]`` lines)
go to stdout; failures and prompts (no active session, refused delete,
corrupt config) go to stderr alongside a non-zero return code. Credential
*values* are never printed by any built-in — only names/keys/status.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path

from loguru import logger

from mcp_core.relay import try_open_browser
from mcp_core.storage.backends import backend_from_env
from mcp_core.storage.mode import clear_mode, get_mode
from mcp_core.storage.per_plugin_store import PerPluginStore
from mcp_core.storage.session_lock import SessionInfo, acquire_session_lock, release_session_lock


def ensure_stderr_logging() -> None:
    """Reset loguru to a single stderr sink at ``MCP_LOG_LEVEL`` (default INFO).

    Idempotent: ``logger.remove()`` clears every existing sink first, so
    calling this more than once never leaves duplicate sinks behind.
    """
    logger.remove()
    logger.add(sys.stderr, level=os.environ.get("MCP_LOG_LEVEL", "INFO"))


def _config_status(server_name: str, store: PerPluginStore) -> int:
    payload = store.load()
    if payload is not None:
        print(f"{server_name}: configured (source: file)")
        print("  (env overrides, if any, take precedence at server start)")
        return 0

    # load() returns None for both "absent" and "corrupt" (see
    # PerPluginStore.load docstring/logging); the raw backend read tells
    # them apart without ever touching the plaintext.
    if store._backend.get(store.cred_key) is not None:
        print(
            f"{server_name}: config is corrupt (undecryptable) -- re-run setup to restore",
            file=sys.stderr,
        )
        return 1

    print(f"{server_name}: not configured")
    print("  (env overrides, if any, take precedence at server start)")
    return 0


def _confirm_delete(server_name: str) -> bool:
    print(f"Delete stored config for {server_name}? [y/N] ", end="", file=sys.stderr, flush=True)
    line = sys.stdin.readline().strip().lower()
    return line in ("y", "yes")


def _config_delete(server_name: str, store: PerPluginStore, *, yes: bool) -> int:
    if not yes:
        if not sys.stdin.isatty():
            print(
                f"{server_name}: refusing to delete without --yes in non-interactive mode",
                file=sys.stderr,
            )
            return 1
        if not _confirm_delete(server_name):
            print(f"{server_name}: aborted", file=sys.stderr)
            return 1

    store.clear()
    print(f"{server_name}: config deleted")
    return 0


def _build_config_handler(server_name: str) -> Callable[[argparse.Namespace], int]:
    def _handler(ns: argparse.Namespace) -> int:
        store = PerPluginStore(server_name)
        if ns.config_action == "status":
            return _config_status(server_name, store)
        return _config_delete(server_name, store, yes=ns.yes)

    return _handler


def _relay_status(server_name: str, info: SessionInfo | None) -> int:
    if info is None:
        print(f"{server_name}: no active relay session", file=sys.stderr)
        return 1
    age_s = time.time() - info.created_at
    print(f"{server_name}: session {info.session_id[:8]} relay_url={info.relay_url} age={age_s:.0f}s")
    return 0


def _build_relay_handler(server_name: str) -> Callable[[argparse.Namespace], int]:
    def _handler(ns: argparse.Namespace) -> int:
        if ns.relay_action == "reset":
            asyncio.run(release_session_lock(server_name))
            clear_mode(server_name)
            print(f"{server_name}: relay state cleared")
            return 0

        info = asyncio.run(acquire_session_lock(server_name))
        if ns.relay_action == "status":
            return _relay_status(server_name, info)

        # "open"
        if info is None:
            print(f"{server_name}: no active relay session", file=sys.stderr)
            return 1
        try_open_browser(info.relay_url)
        print(f"{server_name}: opened {info.relay_url}")
        return 0

    return _handler


def _run_doctor(server_name: str) -> int:
    ok = True

    if sys.version_info[:2] == (3, 13):
        print("[ok] python 3.13")
    else:
        print(f"[fail] python {sys.version_info.major}.{sys.version_info.minor} (expected 3.13)")
        ok = False

    try:
        backend_from_env()
        print("[ok] credential backend initializes")
    except Exception as err:
        print(f"[fail] credential backend: {err}")
        ok = False

    # Only check writability if the dir already exists -- doctor must not
    # create it as a side effect (mkdir-probing would leave stray dirs for
    # servers that were never configured).
    store_dir = Path.home() / f".{server_name}-mcp"
    if store_dir.exists():
        if os.access(store_dir, os.W_OK):
            print(f"[ok] store dir writable: {store_dir}")
        else:
            print(f"[fail] store dir not writable: {store_dir}")
            ok = False
    else:
        print(f"[warn] store dir does not exist yet: {store_dir}")

    store = PerPluginStore(server_name)
    payload = store.load()
    if payload is not None:
        print("[ok] config: configured")
    elif store._backend.get(store.cred_key) is not None:
        print("[fail] config: corrupt")
        ok = False
    else:
        print("[warn] config: not configured")

    info = asyncio.run(acquire_session_lock(server_name))
    if info is not None:
        print(f"[ok] relay session active ({info.session_id[:8]})")
    else:
        print("[warn] no active relay session")

    print(f"[ok] mode: {get_mode(server_name) or 'unset'}")

    return 0 if ok else 1


def _build_doctor_handler(server_name: str) -> Callable[[argparse.Namespace], int]:
    def _handler(_ns: argparse.Namespace) -> int:
        return _run_doctor(server_name)

    return _handler


ExtraHandler = Callable[[argparse.Namespace], int]
ExtraSpec = ExtraHandler | tuple[Callable[[argparse.ArgumentParser], None], ExtraHandler]


def build_cli(
    server_name: str,
    *,
    serve: Callable[[list[str]], int | None],
    extra: dict[str, ExtraSpec] | None = None,
    version: str | None = None,
) -> Callable[[list[str] | None], int]:
    """Build the console-script entry point for one MCP server.

    ``extra`` subcommand names take precedence over the reserved built-ins,
    so a server (or a test) can supply its own ``doctor``/``config``/``relay``
    handler instead. ``version`` is accepted here (the built-in handlers below
    do not consume it) so it is already threaded through for a future task
    that wants it.

    Each ``extra`` value is either a bare handler -- registered as an
    argument-less subcommand, as before -- or a ``(configure, handler)``
    tuple, where ``configure`` receives that subcommand's
    ``argparse.ArgumentParser`` (to add positionals/flags) before argv is
    parsed. Overriding a built-in name (``config``/``relay``/``doctor``) with
    a tuple replaces that built-in's own argument wiring entirely.
    """
    handlers: dict[str, ExtraHandler] = {
        "config": _build_config_handler(server_name),
        "relay": _build_relay_handler(server_name),
        "doctor": _build_doctor_handler(server_name),
    }
    configurers: dict[str, Callable[[argparse.ArgumentParser], None]] = {}
    for name, spec in (extra or {}).items():
        configure, handler = spec if isinstance(spec, tuple) else (None, spec)
        handlers[name] = handler
        if configure is not None:
            configurers[name] = configure

    def run(argv: list[str] | None = None) -> int:
        if argv is None:
            argv = sys.argv[1:]

        if not argv:
            rc = serve([])
            return 0 if rc is None else rc

        # Peek argv[0] before touching argparse at all: bare/flag argv must
        # never reach the subparsers below, or `--http` would be misread as
        # an unrecognized option instead of passed through to `serve`.
        if argv[0].startswith("-"):
            rc = serve(argv)
            return 0 if rc is None else rc

        subcommand = argv[0]
        handler = handlers.get(subcommand)
        if handler is None:
            names = ", ".join(sorted(handlers))
            print(
                f"{server_name}: unknown subcommand {subcommand!r} (expected one of: {names})",
                file=sys.stderr,
            )
            return 2

        ensure_stderr_logging()
        parser = argparse.ArgumentParser(prog=server_name)
        subparsers = parser.add_subparsers(dest="subcommand")
        for name in handlers:
            sub = subparsers.add_parser(name)
            # Bad/missing args for these two (e.g. `config` with no action)
            # fall through to argparse's own parser.error() -> SystemExit(2),
            # which is acceptable here -- distinct from the unknown-subcommand
            # case above, which already returns a clean rc 2 without raising.
            if name in configurers:
                configurers[name](sub)
            elif name == "config":
                sub.add_argument("config_action", choices=["status", "delete"])
                sub.add_argument("--yes", action="store_true", default=False)
            elif name == "relay":
                sub.add_argument("relay_action", choices=["status", "open", "reset"])
        ns = parser.parse_args(argv)
        return handler(ns)

    return run
