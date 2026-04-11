"""Thin stdio to HTTP forwarder.

Forwards MCP JSON-RPC frames from stdin to a local HTTP daemon's /mcp
endpoint and writes responses to stdout. Enables agents that only support
stdio transport (e.g., Antigravity) to use HTTP-only MCP servers.

Spawned by the agent as a stdio MCP server. Reads MCP_CORE_SERVER_URL
environment variable (or --url CLI flag) to know where to forward.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

import httpx


async def forward(url: str, token: str | None) -> int:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=None) as client:
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)
        while True:
            line = await reader.readline()
            if not line:
                return 0
            try:
                resp = await client.post(url, content=line, headers=headers)
                sys.stdout.write(resp.text + "\n")
                sys.stdout.flush()
            except httpx.HTTPError as e:
                sys.stderr.write(f"stdio-proxy HTTP error: {e}\n")
                return 2


async def main(url: str | None = None, token: str | None = None) -> int:
    resolved_url = url or os.environ.get("MCP_CORE_SERVER_URL")
    resolved_token = token if token is not None else os.environ.get("MCP_CORE_SERVER_TOKEN")
    if not resolved_url:
        sys.stderr.write("MCP_CORE_SERVER_URL not set. Pass --url <url> or set the env var.\n")
        return 1
    return await forward(resolved_url, resolved_token)


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
    parser.add_argument(
        "--token",
        default=None,
        help="Bearer token (default: $MCP_CORE_SERVER_TOKEN)",
    )
    args = parser.parse_args()
    return asyncio.run(main(url=args.url, token=args.token))


if __name__ == "__main__":
    sys.exit(cli())
