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
from mcp_core.llm.key_rotation import (
    is_rotatable_error,
    rotate_keys,
    split_keys,
)
from mcp_core.llm.provider_catalog import provider_catalog_models
from mcp_core.llm.vertex_express import (
    VertexExpressError,
    acompletion_express,
    completion_express,
    is_express_model,
)

__all__ = [
    "ModelCapabilityError",
    "VertexExpressError",
    "acompletion",
    "acompletion_express",
    "aembedding",
    "aimage_generation",
    "arerank",
    "avideo_content",
    "avideo_generation",
    "avideo_status",
    "check_capability",
    "completion",
    "completion_express",
    "embedding",
    "is_express_model",
    "is_rotatable_error",
    "list_models",
    "provider_catalog_models",
    "rerank",
    "rotate_keys",
    "split_keys",
    "suggest_models",
    "supports_vision",
]
