"""Tests for mcp_embedding_daemon.backends."""

from __future__ import annotations

import pytest

from mcp_embedding_daemon.backends.gguf import GGUFBackend


def test_gguf_backend_not_implemented() -> None:
    backend = GGUFBackend("dummy")
    with pytest.raises(NotImplementedError):
        backend.embed(["test"])
