"""HTTP API for shared embedding daemon.

Exposes /embed (text to vector), /rerank (query + docs to scores), /health.
Used by wet-mcp, mnemo-mcp, better-code-review-graph to share a single
ONNX/GGUF model instance instead of loading per-server.

v0.1.0 alpha: /health works. /embed and /rerank return 501 Not Implemented
with a pointer to the roadmap because the ONNX + GGUF backends ship as
thin adapters around qwen3-embed in a follow-up release.
"""

from __future__ import annotations

from typing import Protocol

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from pydantic import BaseModel


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
router = APIRouter()

NOT_IMPLEMENTED_DETAIL = (
    "Embedding backend (ONNX / GGUF) is not yet wired in v0.1.0. "
    "Track progress at https://github.com/n24q02m/mcp-core/issues"
)


def get_backend() -> Backend | None:
    """Dependency provider for the embedding/rerank backend.

    In v0.1.0, this returns None, causing 501 in the handlers.
    """
    return None


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


@router.post("/embed", response_model=EmbedResponse)
async def embed(req: EmbedRequest, backend: Backend | None = Depends(get_backend)) -> EmbedResponse:
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=NOT_IMPLEMENTED_DETAIL,
        )
    data = backend.embed(req.input)
    return EmbedResponse(data=data, model=req.model, dims=req.dims)


@router.post("/rerank", response_model=RerankResponse)
async def rerank(req: RerankRequest, backend: Backend | None = Depends(get_backend)) -> RerankResponse:
    if backend is None:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=NOT_IMPLEMENTED_DETAIL,
        )
    results_raw = backend.rerank(req.query, req.documents)
    # Convert list[tuple[int, float]] to list[dict]
    results = [{"index": idx, "relevance_score": score} for idx, score in results_raw]

    if req.top_n is not None:
        results = sorted(results, key=lambda x: x["relevance_score"], reverse=True)[: req.top_n]

    return RerankResponse(results=results, model=req.model)


app.include_router(router)
