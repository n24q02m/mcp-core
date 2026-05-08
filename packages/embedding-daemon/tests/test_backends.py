"""Tests for mcp_embedding_daemon.backends."""

from __future__ import annotations

import pytest

from mcp_embedding_daemon.backends.gguf import GGUFBackend
from mcp_embedding_daemon.backends.onnx import ONNXBackend


def test_gguf_backend_not_implemented() -> None:
    backend = GGUFBackend("dummy")
    with pytest.raises(NotImplementedError):
        backend.embed(["test"])


def test_onnx_backend_not_implemented() -> None:
    backend = ONNXBackend("dummy")
    with pytest.raises(NotImplementedError):
        backend.embed(["test"])
    with pytest.raises(NotImplementedError):
        backend.rerank("query", ["doc"])
