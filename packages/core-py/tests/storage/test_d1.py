import json
from unittest.mock import MagicMock, patch

import pytest

from mcp_core.storage import D1Backend, d1_backend_from_env


def test_d1_execute_returns_rows():
    class Http:
        def request(self, method, url, data=None, headers=None):
            assert method == "POST" and url == "http://d1.internal/query"
            payload = json.loads(data.decode())
            assert payload["sql"].startswith("SELECT")
            assert payload["params"] == ["alpha"]
            return (200, json.dumps({"results": [{"id": "c1", "name": "alpha"}]}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    assert db.execute("SELECT * FROM memories WHERE category = ?", ["alpha"]) == [{"id": "c1", "name": "alpha"}]


def test_d1_fetchall_and_fetchone():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (200, json.dumps({"results": [{"id": "c1"}, {"id": "c2"}]}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    assert db.fetchall("SELECT id FROM memories", []) == [{"id": "c1"}, {"id": "c2"}]
    assert db.fetchone("SELECT id FROM memories", []) == {"id": "c1"}

    class HttpEmpty:
        def request(self, method, url, data=None, headers=None):
            return (200, json.dumps({"results": []}).encode())

    db_empty = D1Backend(base_url="http://d1.internal", http=HttpEmpty())
    assert db_empty.fetchone("SELECT id FROM memories WHERE 0", []) is None


def test_d1_headers_with_token():
    class Http:
        def request(self, method, url, data=None, headers=None):
            assert headers["Authorization"] == "Bearer mytoken"
            assert headers["Content-Type"] == "application/json"
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", token="mytoken", http=Http())
    db.execute("SELECT 1", [])


def test_d1_executemany_variants():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append(json.loads(data.decode()))
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http(), max_rows_per_insert=2)

    # Empty rows
    db.executemany("INSERT INTO memories (id) VALUES (?)", [])
    assert len(calls) == 0

    # Batched rows (multi-row INSERT expansion)
    db.executemany("INSERT INTO memories (id) VALUES (?)", [["a"], ["b"], ["c"]])
    assert len(calls) == 2
    assert calls[0]["sql"] == "INSERT INTO memories (id) VALUES (?), (?)"
    assert calls[0]["params"] == ["a", "b"]
    assert calls[1]["sql"] == "INSERT INTO memories (id) VALUES (?)"
    assert calls[1]["params"] == ["c"]

    # Non-INSERT or no VALUES match (fallback to loop)
    calls.clear()
    db.executemany("UPDATE memories SET val = ? WHERE id = ?", [[1, "a"], [2, "b"]])
    assert len(calls) == 2
    assert calls[0]["sql"] == "UPDATE memories SET val = ? WHERE id = ?"


def test_d1_executescript():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append(json.loads(data.decode()))
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    db.executescript("CREATE TABLE t1(id); ; INSERT INTO t1 VALUES (1);")
    assert len(calls) == 2
    assert calls[0]["sql"] == "CREATE TABLE t1(id)"
    assert calls[1]["sql"] == "INSERT INTO t1 VALUES (1)"


def test_d1_httpx_http_default():
    # Test the default _HttpxHttp class
    with patch("httpx.request") as mock_request:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"results": []}'
        mock_request.return_value = mock_resp

        db = D1Backend(base_url="http://d1.internal")
        db.execute("SELECT 1", [])

        mock_request.assert_called_once()
        args, kwargs = mock_request.call_args
        assert args[0] == "POST"
        assert args[1] == "http://d1.internal/query"


def test_d1_raises_on_http_error():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (500, b"")

    with pytest.raises(RuntimeError, match="D1Backend"):
        D1Backend(base_url="http://d1.internal", http=Http()).execute("SELECT 1", [])


def test_d1_backend_from_env(monkeypatch):
    monkeypatch.setenv("MCP_D1_BASE_URL", "http://d1.internal")
    monkeypatch.setenv("MCP_D1_TOKEN", "envtoken")
    db = d1_backend_from_env()
    assert db.base_url == "http://d1.internal"
    assert db._token == "envtoken"
