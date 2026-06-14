"""Vertex AI Express generateContent adapter (spec: vertex-express-passthrough).

litellm's ``vertex_ai/`` provider requires a Service Account / ADC and ignores
the Vertex Express API key (open upstream bug BerriAI/litellm#21036). This
module provides a thin, httpx-only branch — selected by the ``vertex_express/``
model prefix in ``dispatch.acompletion`` / ``dispatch.completion`` — that calls
the Express ``generateContent`` REST endpoint directly and translates Google's
response into a litellm-ChatCompletion-shaped object exposing
``.choices[0].message.content`` and ``.usage``.

Endpoint shape verified against google-genai 2.8.0's own request builder
(genai.Client(vertexai=True, api_key=...)):
    POST https://aiplatform.googleapis.com/v1beta1/publishers/google/models/{model}:generateContent
    header: x-goog-api-key: <api_key>
NOT the ``?key=`` query param, and ``v1beta1`` (not ``v1``).

Scope: chat completion ONLY. Vertex Express has no Imagen (:predict) or Veo
(:predictLongRunning) REST surface — image/video generation stays native in
imagine-mcp via the google-genai SDK. No google-genai dependency is added to
mcp-core; this is a pure httpx passthrough.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from mcp_core.http import get_ssrf_safe_async_client, get_ssrf_safe_sync_client, vet_api_base
from mcp_core.http.ssrf import is_multi_user_mode
from mcp_core.llm.catalog import check_capability

VERTEX_EXPRESS_PREFIX = "vertex_express"


@dataclass
class ExpressMessage:
    role: str
    content: str | None


@dataclass
class ExpressChoice:
    message: ExpressMessage
    finish_reason: str | None
    index: int = 0


@dataclass
class ExpressUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class ExpressResponse:
    """litellm-ChatCompletion-shaped: callers read .choices[0].message.content."""

    choices: list[ExpressChoice] = field(default_factory=list)
    usage: ExpressUsage = field(default_factory=ExpressUsage)
    model: str = ""


def is_express_model(model: str) -> bool:
    """True when ``model`` carries the ``vertex_express/`` provider prefix."""
    return model.strip().startswith(f"{VERTEX_EXPRESS_PREFIX}/")


def strip_express_prefix(model: str) -> str:
    """Drop the leading ``vertex_express/`` segment, keep the rest verbatim."""
    return model.strip().split("/", 1)[1]


_DEFAULT_BASE = "https://aiplatform.googleapis.com"
_DEFAULT_API_VERSION = "v1beta1"

# OpenAI chat role -> Vertex generateContent role. "system" is handled
# separately (hoisted to systemInstruction); "tool"/"function" are not
# supported on this passthrough and fall back to "user".
_ROLE_MAP = {"user": "user", "assistant": "model"}


def _content_parts(content: Any) -> list[dict[str, Any]]:
    """Translate an OpenAI message ``content`` to Vertex ``parts``.

    Accepts a plain string or the vision list-of-blocks form
    (``{"type": "text"|"image_url", ...}``). A ``data:<mime>;base64,<data>``
    image_url becomes an ``inlineData`` part; a remote ``http(s)`` image_url is
    rejected (the caller must inline media — matches how imagine-mcp downloads
    via the SSRF-safe client before dispatch).
    """
    if isinstance(content, str):
        return [{"text": content}]
    parts: list[dict[str, Any]] = []
    for block in content:
        btype = block.get("type")
        if btype == "text":
            parts.append({"text": block.get("text", "")})
        elif btype == "image_url":
            url = block.get("image_url", {}).get("url", "")
            if not url.startswith("data:"):
                raise ValueError(
                    "vertex_express only accepts inline data: image URLs; download remote media before dispatch"
                )
            header, _, data = url.partition(",")
            mime = header.removeprefix("data:").split(";", 1)[0] or "image/png"
            parts.append({"inlineData": {"mimeType": mime, "data": data}})
        else:
            raise ValueError(f"unsupported content block type {btype!r}")
    return parts


def messages_to_contents(
    messages: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """OpenAI ``messages`` -> (Vertex ``contents``, optional systemInstruction)."""
    contents: list[dict[str, Any]] = []
    system: dict[str, Any] | None = None
    for msg in messages:
        role = msg.get("role", "user")
        if role == "system":
            sys_parts = _content_parts(msg.get("content", ""))
            system = {"parts": sys_parts} if system is None else {"parts": system["parts"] + sys_parts}
            continue
        contents.append(
            {
                "role": _ROLE_MAP.get(role, "user"),
                "parts": _content_parts(msg.get("content", "")),
            }
        )
    return contents, system


def build_express_request(
    *,
    model: str,
    messages: list[dict[str, Any]],
    api_key: str,
    api_base: str | None,
    temperature: float | None = None,
    max_tokens: int | None = None,
    top_p: float | None = None,
    stop: str | list[str] | None = None,
    response_format: dict[str, Any] | None = None,
    stream: bool | None = None,
    **_ignored: Any,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Build (url, headers, json_body) for an Express generateContent call.

    ``api_base`` overrides the ``https://aiplatform.googleapis.com/<version>``
    prefix (already SSRF-vetted by the caller). The api_key goes in the
    ``x-goog-api-key`` header, never the URL query string.

    Honored OpenAI params (mapped into ``generationConfig``): ``temperature``,
    ``max_tokens`` (-> ``maxOutputTokens``), ``top_p`` (-> ``topP``), ``stop``
    (-> ``stopSequences``), and ``response_format={"type": "json_object"}``
    (-> ``responseMimeType: application/json``). ``stream=True`` is REJECTED
    with ``VertexExpressError`` — this adapter returns a buffered response and
    cannot stream, so silently degrading a streamed request would diverge from
    the litellm path. Any other kwarg (``seed``/``n``/``tools``/...) is not
    supported on this passthrough and is ignored.
    """
    if stream:
        raise VertexExpressError(
            "vertex_express does not support streaming (stream=True); use a litellm provider for streamed completions"
        )

    bare = strip_express_prefix(model)
    base = (api_base or f"{_DEFAULT_BASE}/{_DEFAULT_API_VERSION}").rstrip("/")
    url = f"{base}/publishers/google/models/{bare}:generateContent"
    headers = {"x-goog-api-key": api_key, "Content-Type": "application/json"}

    contents, system = messages_to_contents(messages)
    body: dict[str, Any] = {"contents": contents}
    if system is not None:
        body["systemInstruction"] = system
    gen_config: dict[str, Any] = {}
    if temperature is not None:
        gen_config["temperature"] = temperature
    if max_tokens is not None:
        gen_config["maxOutputTokens"] = max_tokens
    if top_p is not None:
        gen_config["topP"] = top_p
    if stop is not None:
        gen_config["stopSequences"] = [stop] if isinstance(stop, str) else list(stop)
    if response_format is not None and response_format.get("type") == "json_object":
        gen_config["responseMimeType"] = "application/json"
    if gen_config:
        body["generationConfig"] = gen_config
    return url, headers, body


class VertexExpressError(RuntimeError):
    """Vertex Express returned an error, a non-2xx status, or no candidate."""


# Vertex finishReason enum -> OpenAI finish_reason.
_FINISH_MAP = {
    "STOP": "stop",
    "MAX_TOKENS": "length",
    "SAFETY": "content_filter",
    "RECITATION": "content_filter",
    "BLOCKLIST": "content_filter",
    "PROHIBITED_CONTENT": "content_filter",
}


def _join_parts(parts: list[dict[str, Any]]) -> str | None:
    texts = [p.get("text", "") for p in parts if "text" in p]
    return "".join(texts) if texts else None


def translate_response(raw: dict[str, Any], *, model: str) -> ExpressResponse:
    """Translate a Vertex generateContent JSON body to ``ExpressResponse``.

    Raises ``VertexExpressError`` when no candidate is present (e.g. a prompt
    blocked by safety filters surfaces only ``promptFeedback.blockReason``).
    """
    candidates = raw.get("candidates") or []
    if not candidates:
        feedback = raw.get("promptFeedback", {})
        reason = feedback.get("blockReason", "no candidates returned")
        raise VertexExpressError(f"Vertex Express returned no candidate: {reason}")

    cand = candidates[0]
    parts = (cand.get("content") or {}).get("parts") or []
    content = _join_parts(parts)
    vertex_finish = cand.get("finishReason", "STOP")
    finish_reason = _FINISH_MAP.get(vertex_finish, "stop")

    usage_meta = raw.get("usageMetadata") or {}
    usage = ExpressUsage(
        prompt_tokens=int(usage_meta.get("promptTokenCount", 0)),
        completion_tokens=int(usage_meta.get("candidatesTokenCount", 0)),
        total_tokens=int(usage_meta.get("totalTokenCount", 0)),
    )

    return ExpressResponse(
        choices=[
            ExpressChoice(
                message=ExpressMessage(role="assistant", content=content),
                finish_reason=finish_reason,
                index=0,
            )
        ],
        usage=usage,
        model=model,
    )


_REQUEST_TIMEOUT_S = 120.0
_API_KEY_ENV = "GOOGLE_VERTEX_EXPRESS_API_KEY"
_CHAT_MODES = ("chat", "responses", "completion")


def _resolve_api_key(api_key: str | None) -> str:
    key = api_key or os.environ.get(_API_KEY_ENV)
    if not key:
        raise VertexExpressError(f"vertex_express models require an API key (pass api_key= or set {_API_KEY_ENV})")
    return key


def _ssrf_flags() -> dict[str, bool]:
    """SSRF policy for the fixed first-party host / vetted custom base.

    The Google host is public, so allow_private/allow_loopback stay False; a
    vetted loopback api_base in single-user mode is dialled because the
    transport flags mirror vet_api_base's own decision.
    """
    if is_multi_user_mode():
        return {"allow_private": False, "allow_loopback": False}
    return {
        "allow_private": os.environ.get("LLM_API_BASE_ALLOW_PRIVATE") == "1",
        "allow_loopback": True,
    }


def _vet_base(api_base: str | None) -> str | None:
    return vet_api_base(api_base) if api_base else None


async def acompletion_express(
    *,
    model: str,
    messages: list[dict[str, Any]],
    api_key: str | None = None,
    api_base: str | None = None,
    **kwargs: Any,
) -> ExpressResponse:
    """Async Vertex Express generateContent call (litellm#21036 workaround)."""
    key = _resolve_api_key(api_key)
    # Advisory only: litellm's registry has no vertex_express/* entries today,
    # so this passes via the graceful-unknown branch. Kept for forward-compat
    # and parity with the litellm path's capability gate.
    check_capability(model, _CHAT_MODES)
    base = _vet_base(api_base)
    url, headers, body = build_express_request(model=model, messages=messages, api_key=key, api_base=base, **kwargs)
    async with get_ssrf_safe_async_client(**_ssrf_flags()) as client:
        resp = await client.post(url, headers=headers, json=body, timeout=_REQUEST_TIMEOUT_S)
    if resp.status_code // 100 != 2:
        raise VertexExpressError(f"Vertex Express HTTP {resp.status_code}: {resp.text[:500]}")
    return translate_response(resp.json(), model=model)


def completion_express(
    *,
    model: str,
    messages: list[dict[str, Any]],
    api_key: str | None = None,
    api_base: str | None = None,
    **kwargs: Any,
) -> ExpressResponse:
    """Sync Vertex Express generateContent call. Do NOT call from async context."""
    key = _resolve_api_key(api_key)
    # Advisory only: litellm's registry has no vertex_express/* entries today,
    # so this passes via the graceful-unknown branch. Kept for forward-compat
    # and parity with the litellm path's capability gate.
    check_capability(model, _CHAT_MODES)
    base = _vet_base(api_base)
    url, headers, body = build_express_request(model=model, messages=messages, api_key=key, api_base=base, **kwargs)
    with get_ssrf_safe_sync_client(**_ssrf_flags()) as client:
        resp = client.post(url, headers=headers, json=body, timeout=_REQUEST_TIMEOUT_S)
    if resp.status_code // 100 != 2:
        raise VertexExpressError(f"Vertex Express HTTP {resp.status_code}: {resp.text[:500]}")
    return translate_response(resp.json(), model=model)
