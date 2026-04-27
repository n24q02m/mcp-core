"""Run mcp.ClientSession E2E against a running local Docker MCP server.

Connects via Streamable HTTP transport, calls ``initialize`` + ``list_tools``,
verifies that all expected top-level tool names are present. Tools are not
invoked here — that is left to per-server smoke suites because the input
shapes differ.
"""

from __future__ import annotations

import time

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def run_e2e_http(base_url: str, expected_tool_names: list[str]) -> None:
    """Connect, list tools, assert ``expected_tool_names`` is a subset.

    Raises ``AssertionError`` listing the missing names if any expected tool
    is not advertised by the server. Extra tools are tolerated.
    """
    async with streamablehttp_client(f"{base_url}/mcp") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            actual = {t.name for t in tools.tools}
            missing = set(expected_tool_names) - actual
            if missing:
                raise AssertionError(
                    f"Tools missing from {base_url}: {sorted(missing)}; got: {sorted(actual)}"
                )


def wait_for_health(base_url: str, timeout: float = 60.0) -> None:
    """Poll the OAuth metadata endpoint until 200 or timeout.

    Uses ``/.well-known/oauth-authorization-server`` as the readiness signal
    because every MCP server with relay/oauth auth exposes it; ``/health`` is
    not standardized across the stack.
    """
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            r = httpx.get(
                f"{base_url}/.well-known/oauth-authorization-server", timeout=2.0
            )
            if r.status_code == 200:
                return
        except httpx.HTTPError as e:
            last_err = e
        time.sleep(2)
    raise TimeoutError(
        f"{base_url} not healthy after {timeout}s (last error: {last_err})"
    )
