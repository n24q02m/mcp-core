"""HTTP API for shared embedding daemon.

Exposes /embed (text to vector), /rerank (query + docs to scores), /health.
Used by wet-mcp, mnemo-mcp, better-code-review-graph to share a single
ONNX/GGUF model instance instead of loading per-server.
"""
from __future__ import annotations

from fastapi import FastAPI
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


app = FastAPI(title="mcp-embedding-daemon", version="0.1.0")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": "0.1.0"}


@app.post("/embed", response_model=EmbedResponse)
async def embed(req: EmbedRequest) -> EmbedResponse:
    raise NotImplementedError(
        "Wire to backends.onnx / backends.gguf in a follow-up Phase I task"
    )


@app.post("/rerank", response_model=RerankResponse)
async def rerank(req: RerankRequest) -> RerankResponse:
    raise NotImplementedError(
        "Wire to backends.onnx / backends.gguf in a follow-up Phase I task"
    )
