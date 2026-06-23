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


def test_d1_executemany_expands_values_tuple():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append(json.loads(data.decode()))
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http(), max_rows_per_insert=2)
    db.executemany("INSERT INTO memories (id) VALUES (?)", [["a"], ["b"], ["c"]])
    assert len(calls) == 2  # batch of 2 (multi-row) + 1


def test_d1_raises_on_http_error():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (500, b"")

    with pytest.raises(RuntimeError, match="D1Backend"):
        D1Backend(base_url="http://d1.internal", http=Http()).execute("SELECT 1", [])


def test_d1_backend_from_env(monkeypatch):
    monkeypatch.setenv("MCP_D1_BASE_URL", "http://d1.internal")
    assert d1_backend_from_env().base_url == "http://d1.internal"


def test_d1_executemany_nplusone_fallback():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append((method, url, json.loads(data.decode())))
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    # A statement that doesn't match the VALUES regex (e.g. UPDATE)
    sql = "UPDATE t SET x = ? WHERE id = ?"
    rows = [[1, "a"], [2, "b"], [3, "c"]]

    db.executemany(sql, rows)

    # Should make 1 call to /batch instead of 3 to /query
    assert len(calls) == 1
    assert calls[0][1] == "http://d1.internal/batch"
    assert isinstance(calls[0][2], list)
    assert len(calls[0][2]) == 3
    assert calls[0][2][0]["sql"] == sql
    assert calls[0][2][0]["params"] == [1, "a"]


def test_d1_executemany_single_row_still_uses_query():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append((method, url, json.loads(data.decode())))
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    sql = "UPDATE t SET x = ? WHERE id = ?"
    rows = [[1, "a"]]

    db.executemany(sql, rows)

    # Single row should still use /query for efficiency/compatibility
    assert len(calls) == 1
    assert calls[0][1] == "http://d1.internal/query"
    assert isinstance(calls[0][2], dict)
    assert calls[0][2]["sql"] == sql
