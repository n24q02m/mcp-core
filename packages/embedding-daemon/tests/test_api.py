"""Tests for mcp_embedding_daemon.api."""

from __future__ import annotations

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from mcp_embedding_daemon.api import __version__, app, get_backend


def test_health_returns_ok() -> None:
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": __version__}


def test_embed_returns_501_with_roadmap_link() -> None:
    client = TestClient(app)
    resp = client.post("/embed", json={"input": ["hello world"]})
    assert resp.status_code == 501
    body = resp.json()
    assert "not yet wired" in body["detail"]
    assert "github.com/n24q02m/mcp-core" in body["detail"]


def test_rerank_returns_501_with_roadmap_link() -> None:
    client = TestClient(app)
    resp = client.post(
        "/rerank",
        json={"query": "test", "documents": ["doc a", "doc b"]},
    )
    assert resp.status_code == 501
    body = resp.json()
    assert "not yet wired" in body["detail"]


def test_embed_validates_input_schema() -> None:
    client = TestClient(app)
    # Missing required `input` field.
    resp = client.post("/embed", json={})
    assert resp.status_code == 422


def test_rerank_validates_input_schema() -> None:
    client = TestClient(app)
    # Missing required `query` and `documents` fields.
    resp = client.post("/rerank", json={})
    assert resp.status_code == 422


def test_embed_success_with_mock_backend() -> None:
    mock_backend = MagicMock()
    mock_backend.embed.return_value = [[0.1, 0.2, 0.3]]

    client = TestClient(app)
    app.dependency_overrides[get_backend] = lambda: mock_backend
    try:
        resp = client.post("/embed", json={"input": ["hello world"]})
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"] == [[0.1, 0.2, 0.3]]
        assert body["model"] == "qwen3-0.6b"
        assert body["dims"] == 768
        mock_backend.embed.assert_called_once_with(["hello world"])
    finally:
        app.dependency_overrides.clear()


def test_rerank_success_with_mock_backend() -> None:
    mock_backend = MagicMock()
    mock_backend.rerank.return_value = [(0, 0.9), (1, 0.1)]

    client = TestClient(app)
    app.dependency_overrides[get_backend] = lambda: mock_backend
    try:
        resp = client.post(
            "/rerank",
            json={"query": "test", "documents": ["doc a", "doc b"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["results"] == [
            {"index": 0, "relevance_score": 0.9},
            {"index": 1, "relevance_score": 0.1},
        ]
        assert body["model"] == "qwen3-rerank-0.6b"
        mock_backend.rerank.assert_called_once_with("test", ["doc a", "doc b"])
    finally:
        app.dependency_overrides.clear()


def test_rerank_top_n_with_mock_backend() -> None:
    mock_backend = MagicMock()
    # Scored out of order to test sorting
    mock_backend.rerank.return_value = [(0, 0.1), (1, 0.9), (2, 0.5)]

    client = TestClient(app)
    app.dependency_overrides[get_backend] = lambda: mock_backend
    try:
        resp = client.post(
            "/rerank",
            json={"query": "test", "documents": ["a", "b", "c"], "top_n": 2},
        )
        assert resp.status_code == 200
        body = resp.json()
        # Should be sorted by score descending and limited to top_n=2
        assert body["results"] == [
            {"index": 1, "relevance_score": 0.9},
            {"index": 2, "relevance_score": 0.5},
        ]
    finally:
        app.dependency_overrides.clear()
