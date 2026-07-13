"""Tests for ``register_open_relay_tool`` -- HTTP-only mode + URL elicitation."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

from mcp_core.relay.tool_helpers import (
    _build_open_relay_handler,
    _client_supports_url_elicitation,
    _run_open_relay,
)


def test_returns_authorize_url_when_public_url_set(monkeypatch) -> None:
    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._try_open_browser",
        lambda url: True,
    )
    handler = _build_open_relay_handler("test-server", "http://127.0.0.1:8080")
    result = handler()
    assert result["url"] == "http://127.0.0.1:8080/authorize"
    assert result["status"] == "unconfigured"
    assert result["browser_opened"] is True


def test_strips_trailing_slash_in_public_url(monkeypatch) -> None:
    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._try_open_browser",
        lambda url: True,
    )
    handler = _build_open_relay_handler("test-server", "http://127.0.0.1:8080/")
    result = handler()
    assert result["url"] == "http://127.0.0.1:8080/authorize"


def test_returns_stdio_unsupported_when_public_url_none() -> None:
    handler = _build_open_relay_handler("test-server", None)
    result = handler()
    assert result["status"] == "stdio_unsupported"
    assert result["url"] == ""
    assert result["browser_opened"] is False


def test_browser_open_failure_still_returns_url(monkeypatch) -> None:
    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._try_open_browser",
        lambda url: False,
    )
    handler = _build_open_relay_handler("test-server", "http://127.0.0.1:8080")
    result = handler()
    assert result["url"] == "http://127.0.0.1:8080/authorize"
    assert result["browser_opened"] is False


def test_handler_docstring_replacement() -> None:
    handler = _build_open_relay_handler("my-special-server", "http://localhost")
    if handler.__doc__ is not None:
        assert "my-special-server" in handler.__doc__
        assert "{server_name}" not in handler.__doc__


# --- Capability detection --------------------------------------------------


def _session(url_cap: object | None, action: str = "accept") -> SimpleNamespace:
    """Build a duck-typed ServerSession stand-in.

    ``url_cap`` is placed at ``client_params.capabilities.elicitation.url``;
    pass ``None`` to simulate a client that did not declare URL elicitation.
    """
    return SimpleNamespace(
        client_params=SimpleNamespace(
            capabilities=SimpleNamespace(
                elicitation=SimpleNamespace(url=url_cap),
            ),
        ),
        elicit_url=AsyncMock(return_value=SimpleNamespace(action=action)),
    )


def test_supports_url_elicitation_true_when_url_capability_present() -> None:
    assert _client_supports_url_elicitation(_session(object())) is True


def test_supports_url_elicitation_false_when_url_capability_none() -> None:
    assert _client_supports_url_elicitation(_session(None)) is False


def test_supports_url_elicitation_false_when_elicitation_missing() -> None:
    session = SimpleNamespace(
        client_params=SimpleNamespace(capabilities=SimpleNamespace(elicitation=None)),
    )
    assert _client_supports_url_elicitation(session) is False


def test_supports_url_elicitation_false_when_client_params_none() -> None:
    session = SimpleNamespace(client_params=None)
    assert _client_supports_url_elicitation(session) is False


def test_supports_url_elicitation_false_when_session_none() -> None:
    assert _client_supports_url_elicitation(None) is False


# --- URL elicitation path --------------------------------------------------


async def test_run_open_relay_elicits_when_capability_present(monkeypatch) -> None:
    browser = AsyncMock()
    monkeypatch.setattr("mcp_core.relay.tool_helpers._try_open_browser", browser)
    session = _session(object(), action="accept")

    result = await _run_open_relay("test-server", "http://127.0.0.1:8080", session)

    session.elicit_url.assert_awaited_once()
    kwargs = session.elicit_url.await_args.kwargs
    assert kwargs["url"] == "http://127.0.0.1:8080/authorize"
    assert "test-server" in kwargs["message"]
    assert isinstance(kwargs["elicitation_id"], str) and kwargs["elicitation_id"]
    # The client opens the URL in URL-mode; the server must NOT open a browser.
    browser.assert_not_called()
    assert result == {
        "url": "http://127.0.0.1:8080/authorize",
        "browser_opened": False,
        "status": "unconfigured",
        "elicitation": "accepted",
    }


async def test_run_open_relay_maps_declined_action() -> None:
    session = _session(object(), action="decline")
    result = await _run_open_relay("test-server", "http://127.0.0.1:8080", session)
    assert result["elicitation"] == "declined"


async def test_run_open_relay_maps_cancelled_action() -> None:
    session = _session(object(), action="cancel")
    result = await _run_open_relay("test-server", "http://127.0.0.1:8080", session)
    assert result["elicitation"] == "cancelled"


async def test_run_open_relay_strips_trailing_slash_in_elicit_url() -> None:
    session = _session(object())
    await _run_open_relay("test-server", "http://127.0.0.1:8080/", session)
    assert session.elicit_url.await_args.kwargs["url"] == "http://127.0.0.1:8080/authorize"


async def test_run_open_relay_falls_back_when_no_capability(monkeypatch) -> None:
    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._try_open_browser",
        lambda url: True,
    )
    session = _session(None)  # client declared NO url elicitation

    result = await _run_open_relay("test-server", "http://127.0.0.1:8080", session)

    session.elicit_url.assert_not_called()
    # Fallback invariant: EXACT legacy dict, no "elicitation" key.
    assert result == {
        "url": "http://127.0.0.1:8080/authorize",
        "browser_opened": True,
        "status": "unconfigured",
    }
    assert "elicitation" not in result


async def test_run_open_relay_falls_back_when_session_none(monkeypatch) -> None:
    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._try_open_browser",
        lambda url: False,
    )
    result = await _run_open_relay("test-server", "http://127.0.0.1:8080", None)
    assert result == {
        "url": "http://127.0.0.1:8080/authorize",
        "browser_opened": False,
        "status": "unconfigured",
    }


async def test_run_open_relay_stdio_unsupported_regardless_of_session() -> None:
    session = _session(object())
    result = await _run_open_relay("test-server", None, session)
    assert result == {"url": "", "browser_opened": False, "status": "stdio_unsupported"}
    session.elicit_url.assert_not_called()


# --- Tool registration wiring ---------------------------------------------


async def test_register_open_relay_tool_http(monkeypatch) -> None:
    from unittest.mock import MagicMock

    from mcp_core.relay.tool_helpers import register_open_relay_tool

    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._try_open_browser",
        lambda url: True,
    )

    mcp = MagicMock()
    register_open_relay_tool(mcp, "test-server", "http://127.0.0.1:8080")

    mcp.tool.assert_called_once()
    _args, kwargs = mcp.tool.call_args
    assert kwargs["name"] == "config__open_relay"
    assert "test-server" in kwargs["description"]

    decorator = mcp.tool.return_value
    decorator.assert_called_once()
    registered_func = decorator.call_args[0][0]

    # A client without url elicitation -> legacy dict (fallback wiring).
    ctx = SimpleNamespace(session=_session(None))
    result = await registered_func(ctx)
    assert result["url"] == "http://127.0.0.1:8080/authorize"
    assert result["status"] == "unconfigured"
    assert "elicitation" not in result


async def test_register_open_relay_tool_http_elicits(monkeypatch) -> None:
    from unittest.mock import MagicMock

    from mcp_core.relay.tool_helpers import register_open_relay_tool

    monkeypatch.setattr(
        "mcp_core.relay.tool_helpers._try_open_browser",
        lambda url: True,
    )

    mcp = MagicMock()
    register_open_relay_tool(mcp, "test-server", "http://127.0.0.1:8080")
    registered_func = mcp.tool.return_value.call_args[0][0]

    session = _session(object(), action="accept")
    ctx = SimpleNamespace(session=session)
    result = await registered_func(ctx)

    session.elicit_url.assert_awaited_once()
    assert result["elicitation"] == "accepted"


async def test_register_open_relay_tool_stdio() -> None:
    from unittest.mock import MagicMock

    from mcp_core.relay.tool_helpers import register_open_relay_tool

    mcp = MagicMock()
    register_open_relay_tool(mcp, "test-server", None)

    mcp.tool.assert_called_once()
    registered_func = mcp.tool.return_value.call_args[0][0]

    ctx = SimpleNamespace(session=_session(object()))
    result = await registered_func(ctx)
    assert result["status"] == "stdio_unsupported"
    assert result["url"] == ""
