"""Regression tests for smart_stdio proxy.

Covers the 2026-04-24 bug where ``httpx_sse.connect_sse`` unconditionally
overwrote the ``Accept`` header with ``text/event-stream``, causing FastMCP
3.2+ servers to reject the stdio-proxy's initial POST with 406 Not
Acceptable. The fix replaces ``httpx_sse`` with a local SSE parser so the
caller keeps full control of the request headers.
"""

from __future__ import annotations

import httpx

from mcp_core.transport.smart_stdio import _iter_sse


def _make_response(body: str) -> httpx.Response:
    """Build a real ``httpx.Response`` backed by in-memory bytes.

    Using the real class (not a mock) so our iterator exercises the same
    ``iter_lines`` code path as production.
    """
    stream = httpx.ByteStream(body.encode("utf-8"))
    return httpx.Response(status_code=200, stream=stream)


def test_iter_sse_single_event():
    body = "event: endpoint\ndata: /mcp?sessionId=abc\n\n"
    events = list(_iter_sse(_make_response(body)))
    assert len(events) == 1
    assert events[0].event == "endpoint"
    assert events[0].data == "/mcp?sessionId=abc"


def test_iter_sse_default_event_is_message():
    body = "data: hello\n\n"
    events = list(_iter_sse(_make_response(body)))
    assert len(events) == 1
    assert events[0].event == "message"
    assert events[0].data == "hello"


def test_iter_sse_multiline_data_concat_with_newline():
    # Per WHATWG spec, multiple ``data:`` lines in one event concatenate
    # with ``\n``. MCP currently doesn't rely on this but we preserve it
    # so future SSE consumers don't lose content.
    body = "data: line1\ndata: line2\n\n"
    events = list(_iter_sse(_make_response(body)))
    assert len(events) == 1
    assert events[0].data == "line1\nline2"


def test_iter_sse_multiple_events():
    body = "event: endpoint\ndata: /mcp\n\nevent: message\ndata: {}\n\n"
    events = list(_iter_sse(_make_response(body)))
    assert [(e.event, e.data) for e in events] == [("endpoint", "/mcp"), ("message", "{}")]


def test_iter_sse_comments_ignored():
    body = ": keep-alive comment\ndata: real\n\n"
    events = list(_iter_sse(_make_response(body)))
    assert len(events) == 1
    assert events[0].data == "real"


def test_iter_sse_trailing_data_without_blank_line():
    # Some servers close the stream without a terminal blank line. We
    # still flush the pending event so the caller doesn't lose the final
    # message.
    body = "event: message\ndata: final"
    events = list(_iter_sse(_make_response(body)))
    assert len(events) == 1
    assert events[0].event == "message"
    assert events[0].data == "final"


def test_iter_sse_handles_optional_space_after_colon():
    # Per WHATWG spec the leading space after ``:`` is optional and
    # stripped when present. Missing space is also valid.
    body = "data:no-space\n\ndata: with-space\n\n"
    events = list(_iter_sse(_make_response(body)))
    assert [e.data for e in events] == ["no-space", "with-space"]
