"""Passthrough wrappers around litellm (spec D2).

Each wrapper does exactly three things before delegating to litellm:
(1) vet user-supplied api_base (SSRF, spec D4); (2) graceful capability check
(spec D3); (3) call the matching litellm function. NO retry/fallback here —
retry policy is server-owned.

litellm functions are looked up as module attributes at call time (via
``_get_litellm()``), never imported as names — keeps monkeypatching and
litellm's lazy loading intact.
"""

from __future__ import annotations

from typing import Any

from mcp_core.http import vet_api_base
from mcp_core.llm.catalog import _get_litellm, check_capability

_CHAT_MODES = ("chat", "responses", "completion")


def _prep_api_base(api_base: str | None) -> str | None:
    if api_base:
        return vet_api_base(api_base)
    return None


async def acompletion(
    *,
    model: str,
    messages: list[dict],
    api_base: str | None = None,
    api_key: str | None = None,
    **kwargs: Any,
) -> Any:
    litellm = _get_litellm()
    api_base = _prep_api_base(api_base)
    check_capability(model, _CHAT_MODES)
    return await litellm.acompletion(
        model=model,
        messages=messages,
        api_base=api_base,
        api_key=api_key,
        **kwargs,
    )


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
    return await litellm.aembedding(model=model, input=input, api_base=api_base, api_key=api_key, **kwargs)


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
    return await litellm.arerank(
        model=model,
        query=query,
        documents=documents,
        api_base=api_base,
        api_key=api_key,
        **kwargs,
    )


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
    return await litellm.aimage_generation(model=model, prompt=prompt, api_base=api_base, api_key=api_key, **kwargs)


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
    return await litellm.avideo_generation(model=model, prompt=prompt, api_base=api_base, api_key=api_key, **kwargs)


async def avideo_status(*, video_id: str, api_key: str | None = None, **kwargs: Any) -> Any:
    return await _get_litellm().avideo_status(video_id=video_id, api_key=api_key, **kwargs)


async def avideo_content(*, video_id: str, api_key: str | None = None, **kwargs: Any) -> Any:
    return await _get_litellm().avideo_content(video_id=video_id, api_key=api_key, **kwargs)


# --- Sync mirrors (crg embeddings/summarizer run in sync contexts — spec D9) ---


def completion(
    *,
    model: str,
    messages: list[dict],
    api_base: str | None = None,
    api_key: str | None = None,
    **kwargs: Any,
) -> Any:
    litellm = _get_litellm()
    api_base = _prep_api_base(api_base)
    check_capability(model, _CHAT_MODES)
    return litellm.completion(model=model, messages=messages, api_base=api_base, api_key=api_key, **kwargs)


def embedding(
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
    return litellm.embedding(model=model, input=input, api_base=api_base, api_key=api_key, **kwargs)


def rerank(
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
    return litellm.rerank(
        model=model,
        query=query,
        documents=documents,
        api_base=api_base,
        api_key=api_key,
        **kwargs,
    )
