"""Backend protocol for embedding and reranking."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Backend(Protocol):
    """Protocol for embedding and reranking backends."""

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Embed a list of texts into vectors."""
        ...

    def rerank(self, query: str, docs: list[str]) -> list[tuple[int, float]]:
        """Rerank a list of documents based on a query. Returns list of (index, score)."""
        ...
