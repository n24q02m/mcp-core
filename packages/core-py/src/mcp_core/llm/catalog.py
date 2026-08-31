"""Model catalog helpers on top of litellm.model_cost (spec D3/D6).

Registry coverage is INCOMPLETE by design — models like
``jina_ai/jina-embeddings-v5-text-small`` or ``xai/grok-4-fast`` are valid yet
absent. Every check here must therefore be graceful-on-missing: unknown model
=> allow passthrough.
"""

from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
from typing import Any

from loguru import logger


class ModelCapabilityError(ValueError):
    """Model exists in the litellm registry but has an incompatible mode."""


def _get_litellm() -> Any:
    os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
    try:
        import litellm
    except ImportError as e:  # pragma: no cover - exercised in no-extra CI leg
        raise RuntimeError("LLM features require the optional extra: pip install 'n24q02m-mcp-core[llm]'") from e
    # Idempotent hardening: never log prompts/keys from inside litellm.
    # Upstream declares `suppress_debug_info = False` unannotated, so ty
    # infers Literal[False]; the assignment is valid at runtime.
    litellm.suppress_debug_info = True
    litellm.turn_off_message_logging = True
    return litellm


_MODEL_COST_MAP: dict[str, Any] | None = None


def _get_model_cost_map() -> dict[str, Any]:
    global _MODEL_COST_MAP
    if _MODEL_COST_MAP is not None:
        return _MODEL_COST_MAP

    # Fast path: load static bundled JSON directly without importing litellm
    try:
        spec = importlib.util.find_spec("litellm")
        if spec and spec.origin:
            litellm_dir = Path(spec.origin).parent
            for filename in (
                "model_prices_and_context_window_backup.json",
                "cost.json",
                "model_prices_and_context_window.json",
            ):
                candidate = litellm_dir / filename
                if candidate.is_file():
                    _MODEL_COST_MAP = json.loads(candidate.read_text(encoding="utf-8"))
                    return _MODEL_COST_MAP
    except Exception:
        pass

    try:
        cost = _get_litellm().model_cost
        _MODEL_COST_MAP = cost if isinstance(cost, dict) else {}
    except RuntimeError:
        _MODEL_COST_MAP = {}
    return _MODEL_COST_MAP


# Env-key -> litellm provider prefix (for configured_only filtering).
# Intentionally covers only the provider set used by the n24q02m servers
# (gemini/openai/xai/anthropic/cohere/jina_ai/vertex_express), NOT all litellm
# providers. Passthrough still works for ANY provider; this map only affects
# listing/suggestions.
#
# It deliberately does NOT model the gateway path. When a call is routed through
# the base configured in MCP_LLM_GATEWAY_BASE (see llm/dispatch.py), the
# credential that matters is the gateway's, not the origin provider's — so a
# model that is perfectly callable can still look "unconfigured" here, and a
# provider absent from this table has no row at all. That drift is confined to
# reporting: dispatch never consults this map (no runtime failure), the only
# listing surface in this repo asks for configured_only=False, and
# suggest_models() already falls back to the unfiltered pool when the filtered
# one comes back empty, so error hints never go blank. Teaching it about the
# gateway would mean deciding that "a gateway is configured" implies "every
# provider is configured" — a real semantic choice, and no caller needs it yet.
_PROVIDER_ENV_KEYS: dict[str, str] = {
    "GEMINI_API_KEY": "gemini",
    "GOOGLE_API_KEY": "gemini",
    "OPENAI_API_KEY": "openai",
    "XAI_API_KEY": "xai",
    "ANTHROPIC_API_KEY": "anthropic",
    "COHERE_API_KEY": "cohere",
    "CO_API_KEY": "cohere",
    "JINA_AI_API_KEY": "jina_ai",
    "GOOGLE_VERTEX_EXPRESS_API_KEY": "vertex_express",
}


def _registry_entry(model: str) -> dict | None:
    cost = _get_model_cost_map()
    entry = cost.get(model)
    if entry is not None:
        return entry
    if "/" in model:
        # Registry keys some providers (e.g. anthropic, openai) without prefix.
        # The bare-name fallback is intentionally provider-agnostic: any
        # "<provider>/" prefix falls back to the bare key.
        return cost.get(model.split("/", 1)[1])
    return None


def check_capability(model: str, expected_modes: tuple[str, ...]) -> None:
    """Raise ModelCapabilityError on a KNOWN model with the wrong mode.

    Unknown model => debug log + pass (open passthrough, spec D3). When litellm
    is not installed (no ``[llm]`` extra) the advisory registry lookup cannot
    run, so this also passes through: httpx-only adapters (vertex_express) must
    work without litellm, and litellm-backed providers fail later at the actual
    call with the clear install-the-extra error.
    """
    try:
        entry = _registry_entry(model)
    except RuntimeError:
        logger.debug(f"litellm unavailable; skipping advisory capability check for {model!r}")
        return
    if entry is None:
        logger.debug(f"model {model!r} not in litellm registry; passthrough")
        return
    mode = entry.get("mode")
    if mode is None:
        # Registry metadata entries (e.g. fireworks-ai-* pricing tiers) are
        # dicts without a "mode" key — treat like unknown models.
        logger.debug(f"model {model!r} has no mode in registry; passthrough")
        return
    if mode not in expected_modes:
        hints = suggest_models(expected_modes, limit=5)
        hints_part = f" Compatible examples: {', '.join(hints)}" if hints else ""
        raise ModelCapabilityError(f"model {model!r} has mode={mode!r}, expected one of {expected_modes}.{hints_part}")


def supports_vision(model: str) -> bool | None:
    """True/False from registry; None when the model is unknown."""
    entry = _registry_entry(model)
    if entry is None:
        return None
    return bool(entry.get("supports_vision", False))


def _configured_providers() -> set[str]:
    return {provider for env_key, provider in _PROVIDER_ENV_KEYS.items() if os.environ.get(env_key)}


def _provider_of(model_key: str, entry: dict) -> str:
    provider = entry.get("litellm_provider", "")
    if provider:
        return str(provider)
    if "/" in model_key:
        return model_key.split("/", 1)[0]
    return "openai"


def list_models(
    *,
    modes: tuple[str, ...] | None = None,
    configured_only: bool = True,
    limit: int = 200,
) -> list[dict]:
    """List registry models, filtered by mode + configured provider keys."""
    configured = _configured_providers() if configured_only else None
    out: list[dict] = []
    for key, entry in _get_model_cost_map().items():
        if not isinstance(entry, dict):
            continue
        mode = entry.get("mode")
        if modes is not None and mode not in modes:
            continue
        provider = _provider_of(key, entry)
        if configured is not None and provider not in configured:
            continue
        out.append(
            {
                "model": key,
                "provider": provider,
                "mode": mode,
                "supports_vision": bool(entry.get("supports_vision", False)),
            }
        )
        if len(out) >= limit:
            break
    return out


def suggest_models(modes: tuple[str, ...], limit: int = 5) -> list[str]:
    """Example model names for error messages (configured providers first)."""
    preferred = list_models(modes=modes, configured_only=True, limit=limit)
    pool = preferred or list_models(modes=modes, configured_only=False, limit=limit)
    return [m["model"] for m in pool[:limit]]
