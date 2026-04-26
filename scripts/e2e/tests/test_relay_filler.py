"""Tests for relay_filler: httpx form scrape + POST."""

import httpx
import respx

from e2e.relay_filler import fill_relay_form


@respx.mock
def test_fill_relay_form_extracts_action_and_posts() -> None:
    html = (
        '<html><body><form method="POST" action="/authorize?nonce=abc123">'
        '<input name="NOTION_INTEGRATION_TOKEN" />'
        "</form></body></html>"
    )
    respx.get("http://127.0.0.1:8080/authorize").mock(
        return_value=httpx.Response(200, html=html)
    )
    respx.post("http://127.0.0.1:8080/authorize?nonce=abc123").mock(
        return_value=httpx.Response(200, json={"status": "complete"})
    )

    result = fill_relay_form(
        "http://127.0.0.1:8080",
        creds={"NOTION_INTEGRATION_TOKEN": "secret_xxx", "EXTRA_KEY": "ignored"},
    )

    assert result == {"status": "complete"}


@respx.mock
def test_fill_relay_form_only_posts_known_input_names() -> None:
    """If form has only NOTION_INTEGRATION_TOKEN input, EXTRA_KEY must not
    leak into the POST body — protects against accidentally over-posting
    skret bundle to a server that didn't ask for it."""
    html = (
        '<html><form method="POST" action="/authorize">'
        '<input name="NOTION_INTEGRATION_TOKEN" />'
        "</form></html>"
    )
    respx.get("http://127.0.0.1:8080/authorize").mock(
        return_value=httpx.Response(200, html=html)
    )
    posted: dict = {}

    def capture(request: httpx.Request) -> httpx.Response:
        posted.update(dict(request.url.params))
        body = request.content.decode("utf-8")
        for kv in body.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                posted[k] = v
        return httpx.Response(200, json={"status": "ok"})

    respx.post("http://127.0.0.1:8080/authorize").mock(side_effect=capture)

    fill_relay_form(
        "http://127.0.0.1:8080",
        creds={
            "NOTION_INTEGRATION_TOKEN": "tok",
            "MCP_DCR_SERVER_SECRET": "should_not_leak",
        },
    )
    assert posted.get("NOTION_INTEGRATION_TOKEN") == "tok"
    assert "MCP_DCR_SERVER_SECRET" not in posted


@respx.mock
def test_fill_relay_form_raises_when_no_form() -> None:
    import pytest

    respx.get("http://127.0.0.1:8080/authorize").mock(
        return_value=httpx.Response(200, html="<html>no form here</html>")
    )
    with pytest.raises(RuntimeError, match="form action"):
        fill_relay_form("http://127.0.0.1:8080", creds={})
