"""ONNX backend -- CPU or CUDA ExecutionProvider.

Reuses qwen3-embed repo model loader. Auto-detects CUDA availability.
"""
from __future__ import annotations


class ONNXBackend:
    def __init__(self, model_path: str) -> None:
        self._model_path = model_path

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError(
            "Wire to qwen3-embed in a follow-up Phase I task"
        )

    def rerank(self, query: str, docs: list[str]) -> list[tuple[int, float]]:
        raise NotImplementedError(
            "Wire to qwen3-embed in a follow-up Phase I task"
        )
