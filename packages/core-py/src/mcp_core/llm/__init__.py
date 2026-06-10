"""LLM passthrough primitive — requires extra: pip install 'n24q02m-mcp-core[llm]'."""

from mcp_core.llm.catalog import (
    ModelCapabilityError,
    check_capability,
    list_models,
    suggest_models,
    supports_vision,
)

__all__ = [
    "ModelCapabilityError",
    "check_capability",
    "list_models",
    "suggest_models",
    "supports_vision",
]
