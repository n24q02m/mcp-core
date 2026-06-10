"""Tests for mcp_embedding_daemon.api."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mcp_embedding_daemon.api import __version__, app, get_backend


def test_health_returns_ok() -> None:
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "version": __version__}


def test_embed_returns_501_with_roadmap_link_by_default() -> None:
    client = TestClient(app)
    resp = client.post("/embed", json={"input": ["hello world"]})
    assert resp.status_code == 501
    body = resp.json()
    assert "not yet wired" in body["detail"]
    assert "github.com/n24q02m/mcp-core" in body["detail"]


def test_rerank_returns_501_with_roadmap_link_by_default() -> None:
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


class MockBackend:
    def embed(self, texts: list[str]) -> list[list[float]]:
        return [[0.1, 0.2] for _ in texts]

    def rerank(self, query: str, docs: list[str]) -> list[tuple[int, float]]:
        # Return index and a score based on document length for deterministic testing
        return [(i, float(len(doc))) for i, doc in enumerate(docs)]


@pytest.fixture
def mock_backend():
    backend = MockBackend()
    app.dependency_overrides[get_backend] = lambda: backend
    yield backend
    app.dependency_overrides.clear()


def test_embed_with_mock_backend(mock_backend) -> None:
    client = TestClient(app)
    resp = client.post("/embed", json={"input": ["hello", "world"]})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["data"]) == 2
    assert body["data"][0] == [0.1, 0.2]
    assert body["model"] == "qwen3-0.6b"


def test_rerank_with_mock_backend(mock_backend) -> None:
    client = TestClient(app)
    # MockBackend returns scores based on document length.
    # "doc b" (5 chars) > "a" (1 char)
    resp = client.post(
        "/rerank",
        json={"query": "test", "documents": ["a", "doc b"]},
    )
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 2
    # Should be sorted by score descending
    assert results[0]["index"] == 1
    assert results[0]["relevance_score"] == 5.0
    assert results[1]["index"] == 0
    assert results[1]["relevance_score"] == 1.0


def test_rerank_top_n_with_mock_backend(mock_backend) -> None:
    client = TestClient(app)
    resp = client.post(
        "/rerank",
        json={
            "query": "test",
            "documents": ["short", "very long document", "medium"],
            "top_n": 2
        },
    )
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 2
    # "very long document" (18) > "medium" (6) > "short" (5)
    assert results[0]["index"] == 1
    assert results[1]["index"] == 2
