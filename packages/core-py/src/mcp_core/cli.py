"""Console-script CLI builder shared by every Python MCP server.

``build_cli`` wraps a server's existing ``serve(argv) -> int | None`` entry
point with subcommand dispatch, without changing that entry point's
behaviour for the two invocation shapes it already handles:

- Bare invocation (``argv`` empty) still means "start the server".
- Any flag-prefixed argv (``--http`` etc.) is passed through to ``serve``
  byte-for-byte, so existing ``--http`` semantics are untouched.

A leading *positional* argv[0] is treated as a subcommand name — either one
of the reserved built-ins (``config``/``relay``/``doctor``, wired up by a
later task) or a server-specific one supplied via ``extra`` — and is routed
through argparse instead of ``serve``. STDOUT is the MCP protocol channel in
stdio mode, so only this subcommand path may print to stdout; the ``serve``
path never touches stdout and this module does not add logging to it
(wet/mnemo already own their logging setup there). ``ensure_stderr_logging``
therefore runs on the subcommand path only, right before dispatch.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable

from loguru import logger

_BUILTIN_NAMES = ("config", "relay", "doctor")


def ensure_stderr_logging() -> None:
    """Reset loguru to a single stderr sink at ``MCP_LOG_LEVEL`` (default INFO).

    Idempotent: ``logger.remove()`` clears every existing sink first, so
    calling this more than once never leaves duplicate sinks behind.
    """
    logger.remove()
    logger.add(sys.stderr, level=os.environ.get("MCP_LOG_LEVEL", "INFO"))


def _unimplemented_builtin(name: str) -> Callable[[argparse.Namespace], int]:
    def _handler(_ns: argparse.Namespace) -> int:
        raise NotImplementedError(f"built-in subcommand {name!r} is wired up in a later task")

    return _handler


def build_cli(
    server_name: str,
    *,
    serve: Callable[[list[str]], int | None],
    extra: dict[str, Callable[[argparse.Namespace], int]] | None = None,
    version: str | None = None,
) -> Callable[[list[str] | None], int]:
    """Build the console-script entry point for one MCP server.

    ``extra`` subcommand names take precedence over the reserved built-ins,
    so a server (or a test) can supply its own ``doctor``/``config``/``relay``
    handler before the real built-ins land. ``version`` is accepted here (the
    built-in stubs below do not consume it) so it is already threaded through
    for the real ``doctor``/``config`` handlers a later task adds.
    """
    handlers: dict[str, Callable[[argparse.Namespace], int]] = {
        name: _unimplemented_builtin(name) for name in _BUILTIN_NAMES
    }
    handlers.update(extra or {})

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
            subparsers.add_parser(name)
        ns = parser.parse_args(argv)
        return handler(ns)

    return run
