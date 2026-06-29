"""Tests for ONNX backend."""

from __future__ import annotations

import pytest

from mcp_embedding_daemon.backends.onnx import ONNXBackend


def test_onnx_backend_init() -> None:
    backend = ONNXBackend("path/to/model.onnx")
    assert backend._model_path == "path/to/model.onnx"


def test_onnx_backend_embed_not_implemented() -> None:
    backend = ONNXBackend("dummy")
    with pytest.raises(NotImplementedError) as excinfo:
        backend.embed(["test"])
    assert "Wire to qwen3-embed" in str(excinfo.value)


def test_onnx_backend_rerank_not_implemented() -> None:
    backend = ONNXBackend("dummy")
    with pytest.raises(NotImplementedError) as excinfo:
        backend.rerank("query", ["doc"])
    assert "Wire to qwen3-embed" in str(excinfo.value)
