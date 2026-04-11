"""Thin stdio to HTTP forwarder.

Forwards MCP JSON-RPC frames from stdin to the local HTTP daemon's /mcp
endpoint and writes responses to stdout. Enables agents that only support
stdio transport (e.g., Antigravity) to use HTTP-only MCP servers.

Spawned by the agent as a stdio MCP server. Reads MCP_CORE_SERVER_URL
environment variable to know where to forward.
"""

from __future__ import annotations

import asyncio
import os
import sys

import httpx


async def main() -> int:
    url = os.environ.get("MCP_CORE_SERVER_URL")
    token = os.environ.get("MCP_CORE_SERVER_TOKEN")
    if not url:
        sys.stderr.write("MCP_CORE_SERVER_URL not set\n")
        return 1

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


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
