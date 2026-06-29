import json
import pytest
from unittest.mock import patch, MagicMock
from mcp_core.storage import VectorizeBackend, vectorize_backend_from_env
from mcp_core.storage.vectorize import _HttpxHttp


def test_httpx_http_request():
    with patch("httpx.request") as mock_request:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"ok": true}'
        mock_request.return_value = mock_resp

        http = _HttpxHttp()
        status, content = http.request("GET", "http://test.com", data=b"data", headers={"X-Test": "1"})

        assert status == 200
        assert content == b'{"ok": true}'
        mock_request.assert_called_once_with(
            "GET", "http://test.com", content=b"data", headers={"X-Test": "1"}, timeout=30.0
        )


def test_vectorize_upsert_success():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (200, json.dumps({"mutationId": "m1"}).encode())

    vb = VectorizeBackend(base_url="http://vectorize.internal", idx="i", token="t", http=Http())
    res = vb.upsert([{"id": "v1", "values": [0.1]}])
    assert res == "m1"


def test_vectorize_upsert_failure():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (500, b"error")

    vb = VectorizeBackend(base_url="http://vectorize.internal", idx="i", http=Http())
    with pytest.raises(RuntimeError, match="VectorizeBackend upsert failed: HTTP 500"):
        vb.upsert([{"id": "v1"}])


def test_vectorize_query_success():
    seen = {}

    class Http:
        def request(self, method, url, data=None, headers=None):
            seen.update(json.loads(data.decode()))
            return (200, json.dumps({"matches": [{"id": "v1", "score": 0.9}]}).encode())

    vb = VectorizeBackend(base_url="http://vectorize.internal", idx="i", http=Http())
    assert vb.query([0.1, 0.2], top_k=10, metadata_filter={"sub": "u1"}) == [{"id": "v1", "score": 0.9}]
    assert seen["topK"] == 10
    assert seen["filter"] == {"sub": "u1"}


def test_vectorize_query_caps_topk_at_50():
    class Http:
        def request(self, method, url, data=None, headers=None):
            body = json.loads(data.decode())
            assert body["topK"] == 50
            return (200, json.dumps({"matches": []}).encode())

    vb = VectorizeBackend(base_url="http://vectorize.internal", idx="i", http=Http())
    vb.query([0.1], top_k=100)


def test_vectorize_query_failure():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (404, b"not found")

    vb = VectorizeBackend(base_url="http://vectorize.internal", idx="i", http=Http())
    with pytest.raises(RuntimeError, match="VectorizeBackend query failed: HTTP 404"):
        vb.query([0.1], top_k=1)


def test_vectorize_wait_until_indexed_success():
    polls = {"n": 0}

    class Http:
        def request(self, method, url, data=None, headers=None):
            polls["n"] += 1
            ready = polls["n"] >= 2
            return (200, json.dumps({"ready": ready}).encode())

    vb = VectorizeBackend(base_url="http://vectorize.internal", idx="i", http=Http())
    assert vb.wait_until_indexed(poll_interval=0.01, max_wait=1) is True
    assert polls["n"] == 2


def test_vectorize_wait_until_indexed_timeout():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (200, json.dumps({"ready": False}).encode())

    vb = VectorizeBackend(base_url="http://vectorize.internal", idx="i", http=Http())
    # Use very small max_wait to trigger timeout quickly
    assert vb.wait_until_indexed(poll_interval=0.01, max_wait=0.05) is False


def test_vectorize_backend_from_env(monkeypatch):
    monkeypatch.setenv("MCP_VECTORIZE_BASE_URL", "http://vectorize.internal/")
    monkeypatch.setenv("MCP_VECTORIZE_IDX", "mnemo-vectors")
    monkeypatch.setenv("MCP_VECTORIZE_TOKEN", "secret-token")
    vb = vectorize_backend_from_env()
    assert vb.base_url == "http://vectorize.internal"
    assert vb.idx == "mnemo-vectors"
    assert vb._token == "secret-token"


def test_vectorize_backend_from_env_defaults(monkeypatch):
    monkeypatch.setenv("MCP_VECTORIZE_IDX", "mnemo-vectors")
    monkeypatch.delenv("MCP_VECTORIZE_BASE_URL", raising=False)
    monkeypatch.delenv("MCP_VECTORIZE_TOKEN", raising=False)
    vb = vectorize_backend_from_env()
    assert vb.base_url == "http://vectorize.internal"
    assert vb.idx == "mnemo-vectors"
    assert vb._token is None
