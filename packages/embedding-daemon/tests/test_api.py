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
