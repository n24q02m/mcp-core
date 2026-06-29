"""Tests for GGUF backend."""

from __future__ import annotations

import pytest

from mcp_embedding_daemon.backends.gguf import GGUFBackend


def test_gguf_backend_init() -> None:
    backend = GGUFBackend("path/to/model.gguf")
    assert backend._model_path == "path/to/model.gguf"


def test_gguf_backend_embed_not_implemented() -> None:
    backend = GGUFBackend("dummy")
    with pytest.raises(NotImplementedError) as excinfo:
        backend.embed(["test"])
    assert "Wire to llama-cpp-python" in str(excinfo.value)


def test_gguf_backend_rerank_not_implemented() -> None:
    backend = GGUFBackend("dummy")
    with pytest.raises(NotImplementedError) as excinfo:
        backend.rerank("query", ["doc"])
    assert "Wire to llama-cpp-python" in str(excinfo.value)
