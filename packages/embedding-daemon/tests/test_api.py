"""Tests for mcp_embedding_daemon.api."""

from __future__ import annotations

from fastapi.testclient import TestClient

from mcp_embedding_daemon.api import __version__, app


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


def test_embed_with_optional_fields() -> None:
    client = TestClient(app)
    resp = client.post(
        "/embed",
        json={
            "model": "custom-model",
            "input": ["hello", "world"],
            "dims": 1024,
        },
    )
    assert resp.status_code == 501


def test_rerank_with_optional_fields() -> None:
    client = TestClient(app)
    resp = client.post(
        "/rerank",
        json={
            "model": "custom-rerank-model",
            "query": "find me stuff",
            "documents": ["doc 1", "doc 2"],
            "top_n": 5,
        },
    )
    assert resp.status_code == 501


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


def test_embed_validates_types() -> None:
    client = TestClient(app)
    # `input` should be a list of strings, not a string.
    resp = client.post("/embed", json={"input": "not a list"})
    assert resp.status_code == 422


def test_rerank_validates_types() -> None:
    client = TestClient(app)
    # `documents` should be a list of strings.
    resp = client.post("/rerank", json={"query": "test", "documents": "not a list"})
    assert resp.status_code == 422
