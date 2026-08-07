"""Passthrough wrappers around litellm (spec D2).

Each wrapper does exactly three things before delegating to litellm:
(1) resolve + vet the api_base (SSRF, spec D4) — the caller's value when given,
otherwise the base configured for the stack in ``MCP_LLM_GATEWAY_BASE``;
(2) graceful capability check (spec D3); (3) call the matching litellm function.
NO retry/fallback here — retry policy is server-owned.

litellm functions are looked up as module attributes at call time (via
``_get_litellm()``), never imported as names — keeps monkeypatching and
litellm's lazy loading intact.

Exception: a ``vertex_express/`` model on ``acompletion``/``completion`` is
routed to ``mcp_core.llm.vertex_express`` (direct generateContent over httpx)
because litellm's ``vertex_ai/`` ignores the Express api_key
(BerriAI/litellm#21036). Every other model and every other surface stays a
pure litellm delegation.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from typing import Any

from mcp_core.http import vet_api_base
from mcp_core.llm.catalog import _get_litellm, check_capability
from mcp_core.llm.key_rotation import rotate_keys, split_keys
from mcp_core.llm.providers import key_env_for_model
from mcp_core.llm.vertex_express import (
    acompletion_express,
    completion_express,
    is_express_model,
)

_CHAT_MODES = ("chat", "responses", "completion")


_GATEWAY_BASE_ENV = "MCP_LLM_GATEWAY_BASE"


def _prep_api_base(api_base: str | None) -> str | None:
    """Resolve the effective api_base: the caller wins, else the stack gateway.

    When ``MCP_LLM_GATEWAY_BASE`` is set, calls that pass no ``api_base`` are
    routed to that OpenAI-compatible base instead of going straight to the
    provider. A base read from the environment is vetted exactly like a
    caller-supplied one (spec D4) — configuration is not a reason to skip SSRF
    checks. Nothing configured and nothing passed => unchanged behaviour.
    """
    base = api_base or os.environ.get(_GATEWAY_BASE_ENV, "").strip()
    if base:
        return vet_api_base(base)
    return None


def _opt(api_base: str | None, api_key: str | None) -> dict[str, Any]:
    """Only forward api_base/api_key when the caller actually supplied them.

    Explicit None through litellm's **kwargs path is treated by Pydantic
    (GenericLiteLLMParams) as field-SET — it survives
    ``model_dump(exclude_unset=True)`` and suppresses provider env fallback.
    """
    out: dict[str, Any] = {}
    if api_base is not None:
        out["api_base"] = api_base
    if api_key is not None:
        out["api_key"] = api_key
    return out


async def _maybe_rotate(
    model: str,
    api_key: str | None,
    single: Callable[[str | None], Awaitable[Any]],
) -> Any:
    """Resolve the provider key(s) for an async dispatch call.

    An explicit ``api_key`` is honoured as-is (one call). Otherwise the model's
    provider key env is read as CSV: more than one key rotates on a key-specific
    failure (HTTP 429/401/403, via ``key_rotation.rotate_keys``); a single (or
    absent) key keeps today's behaviour — ``api_key=None`` so litellm reads the
    env itself, with no extra HTTP or behaviour change.
    """
    if api_key is not None:
        return await single(api_key)
    keys = split_keys(os.getenv(key_env_for_model(model)))
    if len(keys) <= 1:
        return await single(None)
    return await rotate_keys(keys, single, label=model)


async def acompletion(
    *,
    model: str,
    messages: list[dict],
    api_base: str | None = None,
    api_key: str | None = None,
    **kwargs: Any,
) -> Any:
    if is_express_model(model):
        # litellm's vertex_ai/ ignores the Express api_key (BerriAI/litellm#21036);
        # route to the direct generateContent adapter. SSRF + (advisory)
        # capability checks happen inside the adapter.
        return await acompletion_express(model=model, messages=messages, api_base=api_base, api_key=api_key, **kwargs)
    litellm = _get_litellm()
    api_base = _prep_api_base(api_base)
    check_capability(model, _CHAT_MODES)

    async def single(key: str | None) -> Any:
        return await litellm.acompletion(model=model, messages=messages, **_opt(api_base, key), **kwargs)

    return await _maybe_rotate(model, api_key, single)


async def aembedding(
    *,
    model: str,
    input: list[str],
    api_base: str | None = None,
    api_key: str | None = None,
    **kwargs: Any,
) -> Any:
    litellm = _get_litellm()
    api_base = _prep_api_base(api_base)
    check_capability(model, ("embedding",))

    async def single(key: str | None) -> Any:
        return await litellm.aembedding(model=model, input=input, **_opt(api_base, key), **kwargs)

    return await _maybe_rotate(model, api_key, single)


async def arerank(
    *,
    model: str,
    query: str,
    documents: list[str],
    api_base: str | None = None,
    api_key: str | None = None,
    **kwargs: Any,
) -> Any:
    litellm = _get_litellm()
    api_base = _prep_api_base(api_base)
    check_capability(model, ("rerank",))

    async def single(key: str | None) -> Any:
        return await litellm.arerank(model=model, query=query, documents=documents, **_opt(api_base, key), **kwargs)

    return await _maybe_rotate(model, api_key, single)


async def aimage_generation(
    *,
    model: str,
    prompt: str,
    api_base: str | None = None,
    api_key: str | None = None,
    **kwargs: Any,
) -> Any:
    litellm = _get_litellm()
    api_base = _prep_api_base(api_base)
    check_capability(model, ("image_generation", "image_edit"))

    async def single(key: str | None) -> Any:
        return await litellm.aimage_generation(model=model, prompt=prompt, **_opt(api_base, key), **kwargs)

    return await _maybe_rotate(model, api_key, single)


async def avideo_generation(
    *,
    model: str,
    prompt: str,
    api_base: str | None = None,
    api_key: str | None = None,
    **kwargs: Any,
) -> Any:
    litellm = _get_litellm()
    api_base = _prep_api_base(api_base)
    check_capability(model, ("video_generation",))

    async def single(key: str | None) -> Any:
        return await litellm.avideo_generation(model=model, prompt=prompt, **_opt(api_base, key), **kwargs)

    return await _maybe_rotate(model, api_key, single)


async def avideo_status(*, video_id: str, api_key: str | None = None, **kwargs: Any) -> Any:
    return await _get_litellm().avideo_status(video_id=video_id, **_opt(None, api_key), **kwargs)


async def avideo_content(*, video_id: str, api_key: str | None = None, **kwargs: Any) -> Any:
    return await _get_litellm().avideo_content(video_id=video_id, **_opt(None, api_key), **kwargs)


# --- Sync mirrors (crg embeddings/summarizer run in sync contexts — spec D9) ---


def completion(
    *,
    model: str,
    messages: list[dict],
    api_base: str | None = None,
    api_key: str | None = None,
    **kwargs: Any,
) -> Any:
    """Sync completion. Do NOT call from an async context — blocks the event loop."""
    if is_express_model(model):
        return completion_express(model=model, messages=messages, api_base=api_base, api_key=api_key, **kwargs)
    litellm = _get_litellm()
    api_base = _prep_api_base(api_base)
    check_capability(model, _CHAT_MODES)
    return litellm.completion(model=model, messages=messages, **_opt(api_base, api_key), **kwargs)


def embedding(
    *,
    model: str,
    input: list[str],
    api_base: str | None = None,
    api_key: str | None = None,
    **kwargs: Any,
) -> Any:
    """Sync embedding. Do NOT call from an async context — blocks the event loop."""
    litellm = _get_litellm()
    api_base = _prep_api_base(api_base)
    check_capability(model, ("embedding",))
    return litellm.embedding(model=model, input=input, **_opt(api_base, api_key), **kwargs)


def rerank(
    *,
    model: str,
    query: str,
    documents: list[str],
    api_base: str | None = None,
    api_key: str | None = None,
    **kwargs: Any,
) -> Any:
    """Sync rerank. Do NOT call from an async context — blocks the event loop."""
    litellm = _get_litellm()
    api_base = _prep_api_base(api_base)
    check_capability(model, ("rerank",))
    return litellm.rerank(model=model, query=query, documents=documents, **_opt(api_base, api_key), **kwargs)
