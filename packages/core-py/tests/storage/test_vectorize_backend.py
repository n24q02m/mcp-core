import json

from mcp_core.storage import VectorizeBackend, vectorize_backend_from_env


def test_vectorize_query_caps_topk_at_50():
    seen = {}

    class Http:
        def request(self, method, url, data=None, headers=None):
            seen.update(json.loads(data.decode()))
            return (200, json.dumps({"matches": [{"id": "v1", "score": 0.9}]}).encode())

    vb = VectorizeBackend(base_url="http://vectorize.internal", idx="i", http=Http())
    assert vb.query([0.1, 0.2], top_k=100, metadata_filter={"sub": "u1"}) == [
        {"id": "v1", "score": 0.9}
    ]
    assert seen["topK"] == 50 and seen["filter"] == {"sub": "u1"}


def test_vectorize_wait_until_indexed_polls_ready():
    polls = {"n": 0}

    class Http:
        def request(self, method, url, data=None, headers=None):
            polls["n"] += 1
            ready = polls["n"] >= 2
            return (200, json.dumps({"ready": ready}).encode())

    vb = VectorizeBackend(base_url="http://vectorize.internal", idx="i", http=Http())
    assert vb.wait_until_indexed(poll_interval=0, max_wait=5) is True
    assert polls["n"] >= 2


def test_vectorize_backend_from_env(monkeypatch):
    monkeypatch.setenv("MCP_VECTORIZE_BASE_URL", "http://vectorize.internal")
    monkeypatch.setenv("MCP_VECTORIZE_IDX", "mnemo-vectors")
    vb = vectorize_backend_from_env()
    assert vb.base_url == "http://vectorize.internal" and vb.idx == "mnemo-vectors"
