"""Tests for client_runner: MCP SDK v2 Streamable HTTP wiring.

These pin the four things the SDK changed between v1 and v2, each of which
broke or would silently degrade this driver:

1. ``streamablehttp_client`` was renamed ``streamable_http_client``.
2. The transport yields TWO streams, not three.
3. The ``auth=`` kwarg is gone; auth rides on a caller-built ``http_client``.
4. The transport runs on ``httpx2``, a separate package from ``httpx`` --
   an ``httpx.Auth`` subclass handed to it is ignored without an error.
"""

import contextlib
from types import SimpleNamespace

import httpx2
import pytest

from e2e import client_runner


def test_bearer_auth_is_an_httpx2_auth() -> None:
    """Item 4. ``httpx`` and ``httpx2`` are distinct packages installed side
    by side. The transport builds an ``httpx2.AsyncClient``, which accepts
    only ``httpx2.Auth``; passing the ``httpx`` flavour drops the JWT with no
    error and the failure surfaces later as a 401."""
    assert issubclass(client_runner._BearerAuth, httpx2.Auth)


def test_bearer_auth_sets_the_authorization_header() -> None:
    request = httpx2.Request("GET", "http://127.0.0.1:8080/mcp")
    yielded = next(client_runner._BearerAuth("jwt-123").auth_flow(request))
    assert yielded.headers["Authorization"] == "Bearer jwt-123"


async def test_run_e2e_http_carries_the_token_on_the_http_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Items 1-3. The token must reach the transport through ``http_client``,
    and the two yielded streams must land on the session unchanged."""
    seen: dict = {}

    @contextlib.asynccontextmanager
    async def fake_transport(url, *, http_client=None, **kwargs):
        seen["url"] = url
        seen["auth"] = getattr(http_client, "auth", None)
        yield ("read-stream", "write-stream")

    class FakeSession:
        def __init__(self, read, write):
            seen["streams"] = (read, write)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def initialize(self):
            seen["initialized"] = True

        async def list_tools(self):
            return SimpleNamespace(tools=[SimpleNamespace(name="alpha")])

    monkeypatch.setattr(client_runner, "streamable_http_client", fake_transport)
    monkeypatch.setattr(client_runner, "ClientSession", FakeSession)

    await client_runner.run_e2e_http(
        "http://127.0.0.1:8080", ["alpha"], access_token="jwt-123"
    )

    assert seen["url"] == "http://127.0.0.1:8080/mcp"
    assert isinstance(seen["auth"], client_runner._BearerAuth)
    assert seen["streams"] == ("read-stream", "write-stream")
    assert seen["initialized"] is True


async def test_run_e2e_http_reports_missing_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextlib.asynccontextmanager
    async def fake_transport(url, *, http_client=None, **kwargs):
        yield ("read-stream", "write-stream")

    class FakeSession:
        def __init__(self, read, write): ...

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def initialize(self): ...

        async def list_tools(self):
            return SimpleNamespace(tools=[SimpleNamespace(name="alpha")])

    monkeypatch.setattr(client_runner, "streamable_http_client", fake_transport)
    monkeypatch.setattr(client_runner, "ClientSession", FakeSession)

    with pytest.raises(AssertionError, match=r"\['beta'\]"):
        await client_runner.run_e2e_http(
            "http://127.0.0.1:8080", ["alpha", "beta"], access_token="jwt-123"
        )


async def test_run_e2e_http_without_a_token_builds_no_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """godot-with-exe runs unauthenticated; the transport must still work."""
    seen: dict = {}

    @contextlib.asynccontextmanager
    async def fake_transport(url, *, http_client=None, **kwargs):
        seen["auth"] = getattr(http_client, "auth", None)
        yield ("read-stream", "write-stream")

    class FakeSession:
        def __init__(self, read, write): ...

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def initialize(self): ...

        async def list_tools(self):
            return SimpleNamespace(tools=[])

    monkeypatch.setattr(client_runner, "streamable_http_client", fake_transport)
    monkeypatch.setattr(client_runner, "ClientSession", FakeSession)

    await client_runner.run_e2e_http("http://127.0.0.1:8080", [])
    assert seen["auth"] is None
