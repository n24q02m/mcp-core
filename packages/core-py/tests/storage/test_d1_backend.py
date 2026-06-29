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


def test_d1_executemany_expands_simple_values_tuple():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append((url, json.loads(data.decode())))
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http(), max_rows_per_insert=2)
    db.executemany("INSERT INTO memories (id) VALUES (?)", [["a"], ["b"], ["c"]])

    # Batch of 2 optimized via expansion (1 call to /query)
    # Plus remaining 1 (1 call to /batch as it is len 1 and no len > 1 condition met,
    # actually logic says if match and len(batch) > 1: optimized, else: /batch)
    assert len(calls) == 2
    assert calls[0][0] == "http://d1.internal/query"
    assert "VALUES (?), (?)" in calls[0][1]["sql"]
    assert calls[1][0] == "http://d1.internal/batch"
    assert len(calls[1][1]) == 1


def test_d1_executemany_uses_batch_for_complex_values():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append((url, json.loads(data.decode())))
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    # Complex VALUES with function call - should NOT be optimized via expansion
    sql = "INSERT INTO memories (id, ts) VALUES (?, datetime('now'))"
    db.executemany(sql, [["a"], ["b"]])

    assert len(calls) == 1
    assert calls[0][0] == "http://d1.internal/batch"
    assert len(calls[0][1]) == 2
    assert calls[0][1][0]["sql"] == sql


def test_d1_executemany_uses_batch_for_non_insert():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append((url, json.loads(data.decode())))
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    sql = "UPDATE memories SET val = ? WHERE id = ?"
    db.executemany(sql, [["v1", "id1"], ["v2", "id2"]])

    assert len(calls) == 1
    assert calls[0][0] == "http://d1.internal/batch"
    assert len(calls[0][1]) == 2


def test_d1_raises_on_http_error():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (500, b"")

    with pytest.raises(RuntimeError, match="D1Backend query failed"):
        D1Backend(base_url="http://d1.internal", http=Http()).execute("SELECT 1", [])


def test_d1_backend_from_env(monkeypatch):
    monkeypatch.setenv("MCP_D1_BASE_URL", "http://d1.internal")
    assert d1_backend_from_env().base_url == "http://d1.internal"


def test_d1_executemany_empty():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append(url)
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    db.executemany("INSERT INTO memories (id) VALUES (?)", [])
    assert len(calls) == 0


def test_d1_fetchall():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (200, json.dumps({"results": [{"id": 1}]}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    assert db.fetchall("SELECT id FROM memories", []) == [{"id": 1}]


def test_d1_fetchone():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (200, json.dumps({"results": [{"id": 1}]}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    assert db.fetchone("SELECT id FROM memories", []) == {"id": 1}

    class HttpNone:
        def request(self, method, url, data=None, headers=None):
            return (200, json.dumps({"results": []}).encode())

    db_none = D1Backend(base_url="http://d1.internal", http=HttpNone())
    assert db_none.fetchone("SELECT id FROM memories", []) is None


def test_d1_executescript():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append(json.loads(data.decode())["sql"])
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    db.executescript("CREATE TABLE t; INSERT INTO t VALUES (1);")
    assert calls == ["CREATE TABLE t", "INSERT INTO t VALUES (1)"]


def test_d1_headers_with_token():
    db = D1Backend(base_url="http://d1.internal", token="secret")
    headers = db._headers()
    assert headers["Authorization"] == "Bearer secret"
    assert headers["Content-Type"] == "application/json"


def test_d1_batch_error():
    class Http:
        def request(self, method, url, data=None, headers=None):
            if "batch" in url:
                return (500, b"")
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    with pytest.raises(RuntimeError, match="D1Backend batch failed"):
        db.executemany("UPDATE t SET x=?", [[1], [2]])
