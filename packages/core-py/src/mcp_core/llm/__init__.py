"""LLM passthrough primitive — requires extra: pip install 'n24q02m-mcp-core[llm]'."""

from mcp_core.llm.catalog import (
    ModelCapabilityError,
    check_capability,
    list_models,
    suggest_models,
    supports_vision,
)
from mcp_core.llm.dispatch import (
    acompletion,
    aembedding,
    aimage_generation,
    arerank,
    avideo_content,
    avideo_generation,
    avideo_status,
    completion,
    embedding,
    rerank,
)

__all__ = [
    "ModelCapabilityError",
    "acompletion",
    "aembedding",
    "aimage_generation",
    "arerank",
    "avideo_content",
    "avideo_generation",
    "avideo_status",
    "check_capability",
    "completion",
    "embedding",
    "list_models",
    "rerank",
    "suggest_models",
    "supports_vision",
]
