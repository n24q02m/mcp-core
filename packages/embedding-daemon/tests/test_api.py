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
    # The default backend (ONNXBackend) currently raises NotImplementedError
    resp = client.post("/embed", json={"input": ["hello world"]})
    assert resp.status_code == 501
    body = resp.json()
    assert "not yet wired" in body["detail"]
    assert "github.com/n24q02m/mcp-core" in body["detail"]


def test_rerank_returns_501_with_roadmap_link() -> None:
    client = TestClient(app)
    # The default backend (ONNXBackend) currently raises NotImplementedError
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


def test_embed_success() -> None:
    mock_backend = MagicMock()
    mock_backend.embed.return_value = [[0.1, 0.2, 0.3]]

    app.dependency_overrides[get_backend] = lambda: mock_backend
    try:
        client = TestClient(app)
        resp = client.post("/embed", json={"input": ["hello"], "model": "test-model", "dims": 3})
        assert resp.status_code == 200
        data = resp.json()
        assert data["data"] == [[0.1, 0.2, 0.3]]
        assert data["model"] == "test-model"
        assert data["dims"] == 3
        mock_backend.embed.assert_called_once_with(["hello"])
    finally:
        app.dependency_overrides.clear()


def test_rerank_success() -> None:
    mock_backend = MagicMock()
    # Returns (index, score)
    mock_backend.rerank.return_value = [(0, 0.5), (1, 0.8), (2, 0.3)]

    app.dependency_overrides[get_backend] = lambda: mock_backend
    try:
        client = TestClient(app)
        resp = client.post(
            "/rerank",
            json={
                "query": "find me",
                "documents": ["doc0", "doc1", "doc2"],
                "model": "rerank-model",
                "top_n": 2,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        # Sorted by score descending: (1, 0.8), (0, 0.5), (2, 0.3)
        # Limited to top_n=2: (1, 0.8), (0, 0.5)
        assert len(data["results"]) == 2
        assert data["results"][0]["index"] == 1
        assert data["results"][0]["relevance_score"] == 0.8
        assert data["results"][0]["document"] == "doc1"
        assert data["results"][1]["index"] == 0
        assert data["results"][1]["relevance_score"] == 0.5
        assert data["results"][1]["document"] == "doc0"
        assert data.get("model") == "rerank-model"

        mock_backend.rerank.assert_called_once_with("find me", ["doc0", "doc1", "doc2"])
    finally:
        app.dependency_overrides.clear()


def test_rerank_no_top_n() -> None:
    mock_backend = MagicMock()
    mock_backend.rerank.return_value = [(0, 0.1), (1, 0.9)]

    app.dependency_overrides[get_backend] = lambda: mock_backend
    try:
        client = TestClient(app)
        resp = client.post(
            "/rerank",
            json={
                "query": "test",
                "documents": ["a", "b"],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["results"]) == 2
        assert data["results"][0]["index"] == 1
        assert data["results"][1]["index"] == 0
    finally:
        app.dependency_overrides.clear()
