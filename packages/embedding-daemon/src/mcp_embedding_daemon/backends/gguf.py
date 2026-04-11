"""GGUF backend via llama-cpp-python.

Used when ONNX unavailable or quantized GGUF preferred for CPU inference.
"""

from __future__ import annotations


class GGUFBackend:
    def __init__(self, model_path: str) -> None:
        self._model_path = model_path

    def embed(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError("Wire to llama-cpp-python in a follow-up Phase I task")
