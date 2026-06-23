"""Live model-list for special providers whose litellm catalog coverage is poor.

Jina embeddings are absent from litellm's ``model_cost`` and Jina reranker
coverage is a single bare-named entry, so the relay dropdown sources Jina models
from Jina's own (keyless, public) list endpoint instead of hardcoding them.

Graceful by contract: any failure (network, parse, shape change) returns a small
static fallback so the relay form always renders. Cohere is intentionally NOT
fetched here -- its list endpoint requires an API key and the relay key field is
``derived`` (only shown after a model is picked), so Cohere models come from the
litellm catalog (normalized in ``credential_form``) instead.
"""

from __future__ import annotations

import re
import time
from typing import Any

from loguru import logger

_JINA_MODELS_URL = "https://api.jina.ai/v1/models"
_TIMEOUT_S = 3.0
_CACHE_TTL_S = 900.0
# Cached on the FETCHED payload (not per task) so one upstream call serves both
# the embedding and rerank tasks. {"jina": {"records": [...], "at": float}}.
_CACHE: dict[str, dict[str, Any]] = {}

_RERANK_NAME_RE = re.compile(r"reranker|colbert", re.IGNORECASE)

# Static fallback if the (undocumented) Jina list endpoint is unreachable or
# changes shape. Both confirmed present + current in the live list 2026-06-23.
_JINA_FALLBACK: dict[str, list[str]] = {
    "embedding": ["jina_ai/jina-embeddings-v5-text-small"],
    "rerank": ["jina_ai/jina-reranker-v3"],
}


def _fetch_json(url: str, timeout: float) -> dict:
    """GET ``url`` (keyless) through the SSRF-safe sync client; return parsed JSON."""
    from mcp_core.http import get_ssrf_safe_sync_client

    with get_ssrf_safe_sync_client() as client:
        resp = client.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json()


def _to_litellm_id(jina_id: str) -> str:
    """``jina-ai/<x>`` (hyphen) -> ``jina_ai/<x>`` (litellm underscore prefix)."""
    bare = jina_id.split("/", 1)[1] if "/" in jina_id else jina_id
    return f"jina_ai/{bare}"


def _jina_records() -> list[dict[str, Any]]:
    """Cached parsed Jina records ``[{id, embed, rerank}]`` (one fetch per TTL).

    Returns ``[]`` on any failure (no caching of failures -> the next call
    retries); the caller substitutes the static fallback.
    """
    entry = _CACHE.get("jina")
    now = time.monotonic()
    if entry is not None and (now - entry["at"]) < _CACHE_TTL_S:
        return entry["records"]
    try:
        payload = _fetch_json(_JINA_MODELS_URL, _TIMEOUT_S)
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            raise ValueError("unexpected Jina /v1/models shape")
        records: list[dict[str, Any]] = []
        for rec in data:
            if not isinstance(rec, dict):
                continue
            jid = rec.get("id") or ""
            if not jid:
                continue
            name = rec.get("name") or jid
            mods = rec.get("output_modalities") or []
            records.append(
                {
                    "id": _to_litellm_id(jid),
                    "embed": "embeddings" in mods,
                    "rerank": bool(_RERANK_NAME_RE.search(jid) or _RERANK_NAME_RE.search(name)),
                }
            )
        _CACHE["jina"] = {"records": records, "at": now}
        return records
    except Exception as e:  # noqa: BLE001 - graceful by contract
        logger.debug(f"provider_catalog: Jina fetch failed: {e!r}; using static fallback")
        return []


def provider_catalog_models(task: str) -> list[str]:
    """Special-provider model ids covering ``task``; ``[]`` for unsupported tasks.

    Currently sources Jina (keyless) for embedding/rerank. Cached on the fetched
    payload with a TTL; any failure falls back to a tiny static list (never
    raises).
    """
    if task not in ("embedding", "rerank"):
        return []
    records = _jina_records()
    if not records:
        return list(_JINA_FALLBACK.get(task, []))
    bucket = "embed" if task == "embedding" else "rerank"
    out = [r["id"] for r in records if r[bucket]]
    return out or list(_JINA_FALLBACK.get(task, []))
