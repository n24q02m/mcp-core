import json

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


def test_d1_fetchall_returns_rows():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (200, json.dumps({"results": [{"id": "c1", "name": "alpha"}]}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    assert db.fetchall("SELECT * FROM memories WHERE category = ?", ["alpha"]) == [{"id": "c1", "name": "alpha"}]


def test_d1_fetchone_returns_row_or_none():
    class Http:
        def __init__(self, empty=False):
            self.empty = empty

        def request(self, method, url, data=None, headers=None):
            if self.empty:
                return (200, json.dumps({"results": []}).encode())
            return (200, json.dumps({"results": [{"id": "c1", "name": "alpha"}]}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    assert db.fetchone("SELECT * FROM memories WHERE category = ?", ["alpha"]) == {"id": "c1", "name": "alpha"}

    db_empty = D1Backend(base_url="http://d1.internal", http=Http(empty=True))
    assert db_empty.fetchone("SELECT * FROM memories WHERE category = ?", ["alpha"]) is None


def test_d1_executemany_empty():
    class Http:
        def request(self, method, url, data=None, headers=None):
            raise AssertionError("Should not be called")

    db = D1Backend(base_url="http://d1.internal", http=Http())
    db.executemany("INSERT INTO x VALUES (?)", [])  # Should return early


def test_d1_executemany_expands_values_tuple():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append(json.loads(data.decode()))
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http(), max_rows_per_insert=2)
    db.executemany("INSERT INTO memories (id) VALUES (?)", [["a"], ["b"], ["c"]])
    assert len(calls) == 2  # batch of 2 (multi-row) + 1


def test_d1_executemany_batch_fallback():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            assert method == "POST" and url == "http://d1.internal/batch"
            calls.append(json.loads(data.decode()))
            return (200, json.dumps([{"results": []}, {"results": []}]).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http(), max_rows_per_insert=2)
    db.executemany("UPDATE memories SET name = ? WHERE id = ?", [["alpha", "c1"], ["beta", "c2"]])
    assert len(calls) == 1
    assert len(calls[0]) == 2
    assert calls[0][0]["sql"] == "UPDATE memories SET name = ? WHERE id = ?"
    assert calls[0][0]["params"] == ["alpha", "c1"]


def test_d1_executemany_batch_fallback_error():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (500, b"")

    db = D1Backend(base_url="http://d1.internal", http=Http(), max_rows_per_insert=2)
    with pytest.raises(RuntimeError, match="D1Backend batch failed"):
        db.executemany("UPDATE memories SET name = ? WHERE id = ?", [["alpha", "c1"], ["beta", "c2"]])


def test_d1_raises_on_http_error():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (500, b"")

    with pytest.raises(RuntimeError, match="D1Backend"):
        D1Backend(base_url="http://d1.internal", http=Http()).execute("SELECT 1", [])


def test_d1_headers():
    db = D1Backend(base_url="http://d1.internal", token="my-token")
    headers = db._headers()
    assert headers["Authorization"] == "Bearer my-token"
    assert headers["Content-Type"] == "application/json"

    db_no_token = D1Backend(base_url="http://d1.internal")
    headers_no_token = db_no_token._headers()
    assert "Authorization" not in headers_no_token
    assert headers_no_token["Content-Type"] == "application/json"


def test_d1_default_httpx_transport(monkeypatch):
    import httpx

    called_args = {}

    def mock_request(method, url, content=None, headers=None, timeout=None):
        called_args["method"] = method
        called_args["url"] = url
        called_args["content"] = content
        called_args["headers"] = headers

        class MockResponse:
            status_code = 200
            content = b'{"results": []}'

        return MockResponse()

    monkeypatch.setattr(httpx, "request", mock_request)

    db = D1Backend(base_url="http://d1.internal")
    db.execute("SELECT 1", [])

    assert called_args["method"] == "POST"
    assert called_args["url"] == "http://d1.internal/query"


def test_d1_executescript():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append(json.loads(data.decode()))
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    db.executescript("CREATE TABLE t1 (id INT); DROP TABLE t2;  ;   ")

    assert len(calls) == 2
    assert calls[0]["sql"] == "CREATE TABLE t1 (id INT)"
    assert calls[1]["sql"] == "DROP TABLE t2"


def test_d1_backend_from_env(monkeypatch):
    monkeypatch.setenv("MCP_D1_BASE_URL", "http://d1.internal")
    monkeypatch.setenv("MCP_D1_TOKEN", "test-token")

    db = d1_backend_from_env()
    assert db.base_url == "http://d1.internal"
    assert db._token == "test-token"
