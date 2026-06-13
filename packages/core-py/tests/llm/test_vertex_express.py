"""Tests for mcp_core.llm.vertex_express — the custom Vertex AI Express
generateContent adapter (litellm bug BerriAI/litellm#21036 workaround).

litellm need NOT be installed for these tests; the adapter is httpx-only.
"""

from __future__ import annotations

import socket

import pytest

from mcp_core.http import SSRFBlockedError
from mcp_core.llm.vertex_express import (
    VERTEX_EXPRESS_PREFIX,
    ExpressChoice,
    ExpressMessage,
    ExpressResponse,
    ExpressUsage,
    acompletion_express,
    build_express_request,
    completion_express,
    is_express_model,
    messages_to_contents,
    strip_express_prefix,
    translate_response,
)


def test_is_express_model_true():
    assert is_express_model("vertex_express/gemini-2.5-flash") is True


def test_is_express_model_false_for_other_providers():
    assert is_express_model("gemini/gemini-2.5-flash") is False
    assert is_express_model("openai/gpt-4o-mini") is False
    assert is_express_model("gpt-4o-mini") is False


def test_is_express_model_false_for_empty():
    assert is_express_model("") is False


def test_strip_express_prefix():
    assert strip_express_prefix("vertex_express/gemini-2.5-flash") == "gemini-2.5-flash"


def test_strip_express_prefix_nested_slash_preserved():
    # Only the first segment is the provider prefix.
    assert strip_express_prefix("vertex_express/publishers/google") == "publishers/google"


def test_express_response_shape_matches_chatcompletion():
    resp = ExpressResponse(
        choices=[
            ExpressChoice(
                message=ExpressMessage(role="assistant", content="hello"),
                finish_reason="stop",
                index=0,
            )
        ],
        usage=ExpressUsage(prompt_tokens=3, completion_tokens=1, total_tokens=4),
        model="vertex_express/gemini-2.5-flash",
    )
    # Downstream reads resp.choices[0].message.content everywhere.
    assert resp.choices[0].message.content == "hello"
    assert resp.choices[0].finish_reason == "stop"
    assert resp.usage.total_tokens == 4
    assert resp.model == "vertex_express/gemini-2.5-flash"


def test_prefix_constant():
    assert VERTEX_EXPRESS_PREFIX == "vertex_express"


def test_build_express_request_url_and_header():
    url, headers, body = build_express_request(
        model="vertex_express/gemini-2.5-flash",
        messages=[{"role": "user", "content": "hi"}],
        api_key="AQ.fake-key",
        api_base=None,
    )
    assert url == (
        "https://aiplatform.googleapis.com/v1beta1/publishers/google/models/gemini-2.5-flash:generateContent"
    )
    assert headers["x-goog-api-key"] == "AQ.fake-key"
    assert headers["Content-Type"] == "application/json"
    # key must NOT leak into the URL query string
    assert "key=" not in url


def test_build_express_request_custom_api_base():
    url, _headers, _body = build_express_request(
        model="vertex_express/gemini-2.5-flash",
        messages=[{"role": "user", "content": "hi"}],
        api_key="AQ.fake-key",
        api_base="https://aiplatform.googleapis.com/v1",
    )
    assert url == ("https://aiplatform.googleapis.com/v1/publishers/google/models/gemini-2.5-flash:generateContent")


def test_messages_to_contents_role_mapping():
    contents, system = messages_to_contents(
        [
            {"role": "system", "content": "be terse"},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"},
            {"role": "user", "content": "bye"},
        ]
    )
    # system is hoisted to systemInstruction, not a content turn
    assert system == {"parts": [{"text": "be terse"}]}
    assert [c["role"] for c in contents] == ["user", "model", "user"]
    assert contents[0]["parts"][0]["text"] == "hi"
    assert contents[1]["role"] == "model"  # assistant -> model


def test_messages_to_contents_multimodal_image_url():
    contents, _system = messages_to_contents(
        [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "what is this"},
                    {
                        "type": "image_url",
                        "image_url": {"url": "data:image/png;base64,aGVsbG8="},
                    },
                ],
            }
        ]
    )
    parts = contents[0]["parts"]
    assert parts[0] == {"text": "what is this"}
    assert parts[1]["inlineData"]["mimeType"] == "image/png"
    assert parts[1]["inlineData"]["data"] == "aGVsbG8="


def test_build_express_request_body_includes_generation_config():
    _url, _headers, body = build_express_request(
        model="vertex_express/gemini-2.5-flash",
        messages=[{"role": "user", "content": "hi"}],
        api_key="AQ.fake-key",
        api_base=None,
        temperature=0.5,
        max_tokens=128,
    )
    assert body["generationConfig"]["temperature"] == 0.5
    assert body["generationConfig"]["maxOutputTokens"] == 128
    assert body["contents"][0]["parts"][0]["text"] == "hi"


def test_translate_response_happy_path():
    raw = {
        "candidates": [
            {
                "content": {"role": "model", "parts": [{"text": "Hello "}, {"text": "world"}]},
                "finishReason": "STOP",
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 5,
            "candidatesTokenCount": 2,
            "totalTokenCount": 7,
        },
    }
    resp = translate_response(raw, model="vertex_express/gemini-2.5-flash")
    assert resp.choices[0].message.content == "Hello world"
    assert resp.choices[0].message.role == "assistant"
    assert resp.choices[0].finish_reason == "stop"  # STOP -> stop
    assert resp.usage.prompt_tokens == 5
    assert resp.usage.completion_tokens == 2
    assert resp.usage.total_tokens == 7
    assert resp.model == "vertex_express/gemini-2.5-flash"


def test_translate_response_finish_reason_mapping():
    raw = {"candidates": [{"content": {"parts": [{"text": "x"}]}, "finishReason": "MAX_TOKENS"}]}
    resp = translate_response(raw, model="vertex_express/m")
    assert resp.choices[0].finish_reason == "length"  # MAX_TOKENS -> length


def test_translate_response_safety_block_maps_to_content_filter():
    raw = {"candidates": [{"finishReason": "SAFETY"}]}
    resp = translate_response(raw, model="vertex_express/m")
    assert resp.choices[0].finish_reason == "content_filter"
    assert resp.choices[0].message.content is None


def test_translate_response_empty_candidates_raises():
    from mcp_core.llm.vertex_express import VertexExpressError

    raw = {
        "promptFeedback": {"blockReason": "SAFETY"},
        "candidates": [],
    }
    with pytest.raises(VertexExpressError) as exc:
        translate_response(raw, model="vertex_express/m")
    assert "SAFETY" in str(exc.value)


def test_translate_response_missing_usage_defaults_zero():
    raw = {"candidates": [{"content": {"parts": [{"text": "ok"}]}, "finishReason": "STOP"}]}
    resp = translate_response(raw, model="vertex_express/m")
    assert resp.usage.total_tokens == 0


def _fake_getaddrinfo(ip: str):
    def fake(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 443))]

    return fake


class _FakeResponse:
    def __init__(self, status_code: int, json_body: dict):
        self.status_code = status_code
        self._json = json_body
        self.text = str(json_body)

    def json(self):
        return self._json


class _FakeAsyncClient:
    def __init__(self, response):
        self._response = response
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, headers=None, json=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "json": json})
        return self._response


async def test_acompletion_express_happy_path(monkeypatch):
    raw = {
        "candidates": [{"content": {"parts": [{"text": "pong"}]}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2},
    }
    fake_client = _FakeAsyncClient(_FakeResponse(200, raw))
    monkeypatch.setattr(
        "mcp_core.llm.vertex_express.get_ssrf_safe_async_client",
        lambda **kw: fake_client,
    )
    resp = await acompletion_express(
        model="vertex_express/gemini-2.5-flash",
        messages=[{"role": "user", "content": "ping"}],
        api_key="AQ.key",
    )
    assert resp.choices[0].message.content == "pong"
    assert fake_client.calls[0]["headers"]["x-goog-api-key"] == "AQ.key"


async def test_acompletion_express_requires_api_key(monkeypatch):
    from mcp_core.llm.vertex_express import VertexExpressError

    with pytest.raises(VertexExpressError) as exc:
        await acompletion_express(
            model="vertex_express/gemini-2.5-flash",
            messages=[{"role": "user", "content": "ping"}],
            api_key=None,
        )
    assert "GOOGLE_VERTEX_EXPRESS_API_KEY" in str(exc.value)


async def test_acompletion_express_non_2xx_raises(monkeypatch):
    from mcp_core.llm.vertex_express import VertexExpressError

    fake_client = _FakeAsyncClient(_FakeResponse(403, {"error": {"message": "denied"}}))
    monkeypatch.setattr(
        "mcp_core.llm.vertex_express.get_ssrf_safe_async_client",
        lambda **kw: fake_client,
    )
    with pytest.raises(VertexExpressError) as exc:
        await acompletion_express(
            model="vertex_express/gemini-2.5-flash",
            messages=[{"role": "user", "content": "ping"}],
            api_key="AQ.key",
        )
    assert "403" in str(exc.value)


async def test_acompletion_express_vets_custom_api_base_multiuser(monkeypatch):
    monkeypatch.setenv("PUBLIC_URL", "https://srv.example.com")
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    with pytest.raises(SSRFBlockedError):
        await acompletion_express(
            model="vertex_express/gemini-2.5-flash",
            messages=[{"role": "user", "content": "ping"}],
            api_key="AQ.key",
            api_base="http://localhost:9999/v1",
        )


def test_completion_express_sync_happy_path(monkeypatch):
    raw = {
        "candidates": [{"content": {"parts": [{"text": "sync-pong"}]}, "finishReason": "STOP"}],
    }

    class _FakeSyncClient:
        def __init__(self):
            self.calls = []

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, headers=None, json=None, timeout=None):
            self.calls.append(url)
            return _FakeResponse(200, raw)

    monkeypatch.setattr(
        "mcp_core.llm.vertex_express._get_ssrf_safe_sync_client",
        lambda **kw: _FakeSyncClient(),
    )
    resp = completion_express(
        model="vertex_express/gemini-2.5-flash",
        messages=[{"role": "user", "content": "ping"}],
        api_key="AQ.key",
    )
    assert resp.choices[0].message.content == "sync-pong"


async def test_acompletion_express_calls_capability_check(monkeypatch):
    raw = {"candidates": [{"content": {"parts": [{"text": "x"}]}, "finishReason": "STOP"}]}
    fake_client = _FakeAsyncClient(_FakeResponse(200, raw))
    monkeypatch.setattr(
        "mcp_core.llm.vertex_express.get_ssrf_safe_async_client",
        lambda **kw: fake_client,
    )
    seen: dict = {}

    def fake_check(model, modes):
        seen["model"] = model
        seen["modes"] = modes

    monkeypatch.setattr("mcp_core.llm.vertex_express.check_capability", fake_check)
    await acompletion_express(
        model="vertex_express/gemini-2.5-flash",
        messages=[{"role": "user", "content": "ping"}],
        api_key="AQ.key",
    )
    # capability check is invoked with the full prefixed model + chat modes
    assert seen["model"] == "vertex_express/gemini-2.5-flash"
    assert "chat" in seen["modes"]


async def test_acompletion_express_capability_check_is_advisory(monkeypatch):
    # An unknown vertex_express model must NOT raise (registry has no such key).
    raw = {"candidates": [{"content": {"parts": [{"text": "x"}]}, "finishReason": "STOP"}]}
    fake_client = _FakeAsyncClient(_FakeResponse(200, raw))
    monkeypatch.setattr(
        "mcp_core.llm.vertex_express.get_ssrf_safe_async_client",
        lambda **kw: fake_client,
    )
    # Use the real check_capability (importorskip litellm) — must pass through.
    pytest.importorskip("litellm")
    resp = await acompletion_express(
        model="vertex_express/totally-unknown-model",
        messages=[{"role": "user", "content": "ping"}],
        api_key="AQ.key",
    )
    assert resp.choices[0].message.content == "x"
