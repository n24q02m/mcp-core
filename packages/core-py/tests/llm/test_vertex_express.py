"""Tests for mcp_core.llm.vertex_express — the custom Vertex AI Express
generateContent adapter (litellm bug BerriAI/litellm#21036 workaround).

litellm need NOT be installed for these tests; the adapter is httpx-only.
"""

from __future__ import annotations

import pytest

from mcp_core.llm.vertex_express import (
    VERTEX_EXPRESS_PREFIX,
    ExpressChoice,
    ExpressMessage,
    ExpressResponse,
    ExpressUsage,
    build_express_request,
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
