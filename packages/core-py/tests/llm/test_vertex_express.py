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
    is_express_model,
    strip_express_prefix,
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
