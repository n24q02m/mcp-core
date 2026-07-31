"""Run mcp.ClientSession E2E against a running local Docker MCP server.

Connects via Streamable HTTP transport with a Bearer JWT obtained from
:mod:`e2e.oauth_client`. Calls ``initialize`` + ``list_tools``, verifies
that all expected top-level tool names are present. Tools are not
invoked here — that is left to per-server smoke suites because the input
shapes differ.
"""

from __future__ import annotations

import time
from collections.abc import Generator

import httpx
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client


class _BearerAuth(httpx2.Auth):
    """Inject ``Authorization: Bearer <token>`` on every request.

    Must derive from ``httpx2.Auth``, not ``httpx.Auth``: the MCP SDK's
    transport runs on httpx2, a separate package installed alongside httpx,
    and its client accepts only the httpx2 flavour. Handing it the httpx one
    drops the JWT with no error -- the failure surfaces later as a 401.

    The transport takes no ``auth`` kwarg of its own; auth rides on the
    ``http_client`` the caller builds, and covers both the SSE GET and the
    JSON POST the transport opens.
    """

    def __init__(self, token: str) -> None:
        self._token = token

    def auth_flow(
        self, request: httpx2.Request
    ) -> Generator[httpx2.Request, httpx2.Response]:
        request.headers["Authorization"] = f"Bearer {self._token}"
        yield request


async def run_e2e_http(
    base_url: str,
    expected_tool_names: list[str],
    access_token: str | None = None,
) -> None:
    """Connect, list tools, assert ``expected_tool_names`` is a subset.

    ``access_token`` is the Bearer JWT issued by the server's local OAuth
    AS (see :func:`e2e.oauth_client.acquire_jwt`). Required for any server
    with auth enforced on ``/mcp`` — only ``godot-with-exe`` runs without.

    Raises ``AssertionError`` listing the missing names if any expected tool
    is not advertised by the server. Extra tools are tolerated.
    """
    auth = _BearerAuth(access_token) if access_token else None
    # A caller-supplied http_client is not entered by the transport, so own
    # its lifecycle here. ``create_mcp_http_client`` keeps the SDK's
    # recommended MCP timeouts that the transport would otherwise apply.
    async with create_mcp_http_client(auth=auth) as http_client:
        async with streamable_http_client(
            f"{base_url}/mcp", http_client=http_client
        ) as (read, write):
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
    """Poll a readiness endpoint until 200 or timeout.

    Tries ``/.well-known/oauth-authorization-server`` first (every server
    with relay/oauth auth exposes it). Falls back to ``/health`` for no-auth
    servers like godot, which omit the OAuth metadata route.
    """
    deadline = time.time() + timeout
    last_err: Exception | None = None
    probes = [
        f"{base_url}/.well-known/oauth-authorization-server",
        f"{base_url}/health",
    ]
    while time.time() < deadline:
        for url in probes:
            try:
                r = httpx.get(url, timeout=2.0)
                if r.status_code == 200:
                    return
            except httpx.HTTPError as e:
                last_err = e
        time.sleep(2)
    raise TimeoutError(
        f"{base_url} not healthy after {timeout}s (last error: {last_err})"
    )
