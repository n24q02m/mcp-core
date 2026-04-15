"""Thin stdio to HTTP forwarder.

Forwards MCP JSON-RPC frames from stdin to a local HTTP daemon's /mcp
endpoint and writes responses to stdout. Enables agents that only support
stdio transport (e.g., Antigravity) to use HTTP-only MCP servers.

Spawned by the agent as a stdio MCP server. Reads MCP_CORE_SERVER_URL
environment variable (or --url CLI flag) to know where to forward.
"""

from __future__ import annotations

import argparse
import os
import queue
import sys
import threading

import httpx


def _stdin_reader(line_queue: queue.Queue[bytes | None]) -> None:
    """Read lines from stdin on a dedicated thread.

    Using asyncio.connect_read_pipe on stdin crashes on Windows
    ProactorEventLoop when stdin is a pipe (OSError WinError 6). A
    blocking thread reader works portably; the HTTP POST itself is the
    latency bottleneck anyway, so there is no benefit to asyncio here.
    """
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            line_queue.put(None)
            return
        line_queue.put(line)


def forward(url: str, token: str | None) -> int:
    # /mcp (StreamableHTTP) negotiates either application/json or text/event-stream
    # responses; the spec requires clients to Accept both. Missing this header
    # makes every server return 406 Not Acceptable.
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    line_queue: queue.Queue[bytes | None] = queue.Queue()
    reader_thread = threading.Thread(target=_stdin_reader, args=(line_queue,), daemon=True)
    reader_thread.start()

    with httpx.Client(timeout=None) as client:
        while True:
            line = line_queue.get()
            if line is None:
                return 0
            try:
                resp = client.post(url, content=line, headers=headers)
                sys.stdout.write(resp.text + "\n")
                sys.stdout.flush()
            except httpx.HTTPError as e:
                sys.stderr.write(f"stdio-proxy HTTP error: {e}\n")
                return 2


def main(url: str | None = None) -> int:
    resolved_url = url or os.environ.get("MCP_CORE_SERVER_URL")
    # Security policy: Token must be sourced from environment variable to prevent leakage
    resolved_token = os.environ.get("MCP_CORE_SERVER_TOKEN")
    if not resolved_url:
        sys.stderr.write("MCP_CORE_SERVER_URL not set. Pass --url <url> or set the env var.\n")
        return 1
    return forward(resolved_url, resolved_token)


def cli() -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-stdio-proxy",
        description="Forward stdio MCP frames to an HTTP MCP server",
    )
    parser.add_argument(
        "--url",
        default=None,
        help="Upstream HTTP MCP endpoint (default: $MCP_CORE_SERVER_URL)",
    )
    args = parser.parse_args()
    return main(url=args.url)


if __name__ == "__main__":
    sys.exit(cli())
