"""Tests for mcp_embedding_daemon.backends.onnx."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mcp_embedding_daemon.backends.onnx import ONNXBackend


def test_onnx_backend_initialization() -> None:
    backend = ONNXBackend("dummy/path/to/model.onnx")
    assert backend._model_path == "dummy/path/to/model.onnx"


def test_onnx_backend_not_implemented() -> None:
    backend = ONNXBackend("dummy")
    with pytest.raises(NotImplementedError):
        backend.embed(["test"])
    with pytest.raises(NotImplementedError):
        backend.rerank("query", ["doc"])


def test_onnx_backend_mock_ort() -> None:
    """Demonstrates how to mock onnxruntime for future implementation."""
    with patch("onnxruntime.InferenceSession") as mock_session:
        mock_instance = MagicMock()
        mock_session.return_value = mock_instance

        # This currently does nothing since the methods raise NotImplementedError,
        # but it shows the pattern requested in the task rationale.
        backend = ONNXBackend("dummy")
        assert backend is not None
