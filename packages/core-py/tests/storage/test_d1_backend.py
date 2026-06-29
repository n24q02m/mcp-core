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


def test_executemany_uses_batch_endpoint():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append((url, json.loads(data.decode())))
            return (
                200,
                json.dumps([{"results": []}, {"results": []}, {"results": []}]).encode(),
            )

    db = D1Backend(base_url="http://d1.internal", http=Http())
    # UPDATE statement won't match the VALUES expansion regex
    rows = [["a", 1], ["b", 2], ["c", 3]]
    db.executemany("UPDATE memories SET val = ? WHERE id = ?", rows)

    # Verify we made ONE call to /batch instead of THREE calls to /query
    assert len(calls) == 1
    url, payload = calls[0]
    assert url == "http://d1.internal/batch"
    assert len(payload) == 3
    assert payload[0]["sql"] == "UPDATE memories SET val = ? WHERE id = ?"
    assert payload[0]["params"] == ["a", 1]


def test_executemany_batch_raises_on_error():
    class Http:
        def request(self, method, url, data=None, headers=None):
            return (500, b"")

    db = D1Backend(base_url="http://d1.internal", http=Http())
    with pytest.raises(RuntimeError, match="D1Backend batch failed"):
        db.executemany("UPDATE x SET y = ?", [[1], [2]])
