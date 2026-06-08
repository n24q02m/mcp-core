"""HTTP API for shared embedding daemon.

Exposes /embed (text to vector), /rerank (query + docs to scores), /health.
Used by wet-mcp, mnemo-mcp, better-code-review-graph to share a single
ONNX/GGUF model instance instead of loading per-server.

v0.1.0 alpha: /health works. /embed and /rerank return 501 Not Implemented
with a pointer to the roadmap because the ONNX + GGUF backends ship as
thin adapters around qwen3-embed in a follow-up release.
"""

from __future__ import annotations

from typing import Annotated, Protocol

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel

from mcp_embedding_daemon.backends.onnx import ONNXBackend


class EmbedRequest(BaseModel):
    model: str = "qwen3-0.6b"
    input: list[str]
    dims: int = 768


class EmbedResponse(BaseModel):
    data: list[list[float]]
    model: str
    dims: int


class RerankRequest(BaseModel):
    model: str = "qwen3-rerank-0.6b"
    query: str
    documents: list[str]
    top_n: int | None = None


class RerankResponse(BaseModel):
    results: list[dict]
    model: str


class HealthResponse(BaseModel):
    status: str
    version: str


class Backend(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...
    def rerank(self, query: str, docs: list[str]) -> list[tuple[int, float]]: ...


__version__ = "0.1.0"

app = FastAPI(title="mcp-embedding-daemon", version=__version__)


NOT_IMPLEMENTED_DETAIL = (
    "Embedding backend (ONNX / GGUF) is not yet wired in v0.1.0. "
    "Track progress at https://github.com/n24q02m/mcp-core/issues"
)


def get_backend() -> Backend:
    """Dependency provider for the embedding backend."""
    # In a future release, this will be a singleton initialized at startup.
    return ONNXBackend(model_path="default")


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


@app.post("/embed", response_model=EmbedResponse)
async def embed(
    req: EmbedRequest,
    backend: Annotated[Backend, Depends(get_backend)],
) -> EmbedResponse:
    try:
        data = backend.embed(req.input)
        return EmbedResponse(data=data, model=req.model, dims=req.dims)
    except NotImplementedError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=NOT_IMPLEMENTED_DETAIL,
        )


@app.post("/rerank", response_model=RerankResponse)
async def rerank(
    req: RerankRequest,
    backend: Annotated[Backend, Depends(get_backend)],
) -> RerankResponse:
    try:
        scores = backend.rerank(req.query, req.documents)
        results = [
            {
                "index": idx,
                "relevance_score": score,
                "document": req.documents[idx],
            }
            for idx, score in scores
        ]
        # Sort by relevance_score descending as per requirement
        results.sort(key=lambda x: x["relevance_score"], reverse=True)
        if req.top_n is not None:
            results = results[: req.top_n]

        return RerankResponse(results=results, model=req.model)
    except NotImplementedError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=NOT_IMPLEMENTED_DETAIL,
        )
