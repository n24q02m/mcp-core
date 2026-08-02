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


class _RecordingHttp:
    """Captures every statement actually put on the wire, /query and /batch alike.

    ``sent`` holds one ``(url, sql, params)`` per *statement*, so a multi-row
    INSERT contributes one entry and a /batch POST contributes one per element.
    D1's 100-parameter cap is per statement, so that is the unit to assert on.
    """

    def __init__(self):
        self.sent = []

    def request(self, method, url, data=None, headers=None):
        payload = json.loads(data.decode())
        stmts = payload if isinstance(payload, list) else [payload]
        for s in stmts:
            self.sent.append((url, s["sql"], s["params"]))
        return (200, json.dumps({"results": []}).encode())


# wet's doc_chunks INSERT, the table that made this bug visible in production:
# 13 columns, so a 100-row chunk would carry 1300 bound parameters.
_WET_DOC_CHUNKS_SQL = (
    "INSERT INTO doc_chunks (id, version_id, library_id, url, title, chunk_index,"
    " content, heading_path, section, topic, content_hash, token_count,"
    " created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
)


def test_d1_executemany_chunks_by_bound_params_not_rows():
    # D1 rejects any query with more than 100 bound parameters. Chunking by rows
    # blows that cap on every table wider than one column: at 13 columns it takes
    # only 8 rows (8 x 13 = 104) to go over, and the default 100-row chunk sends
    # 1300. Every statement that reaches the wire must stay within the cap.
    http = _RecordingHttp()
    rows = [[f"v{r}-{c}" for c in range(13)] for r in range(20)]

    D1Backend(base_url="http://d1.internal", http=http).executemany(_WET_DOC_CHUNKS_SQL, rows)

    over = [(sql[:40], len(params)) for _, sql, params in http.sent if len(params) > 100]
    assert over == [], f"statements exceeding D1's 100-bound-parameter cap: {over}"
    # Every row still gets written exactly once, in order.
    written = [params[i : i + 13] for _, _, params in http.sent for i in range(0, len(params), 13)]
    assert written == rows
    # And each statement's ?-placeholders match the parameters bound to it.
    for _, sql, params in http.sent:
        assert sql.count("?") == len(params)


def test_d1_executemany_rejects_row_wider_than_the_cap():
    # A 101-column row cannot be sent at all -- not even one row per statement.
    # Say so, with the numbers, instead of letting D1 answer "HTTP 400".
    http = _RecordingHttp()
    db = D1Backend(base_url="http://d1.internal", http=http)
    wide_sql = "INSERT INTO wide VALUES (" + ",".join(["?"] * 101) + ")"

    with pytest.raises(ValueError, match=r"101 columns.*100"):
        db.executemany(wide_sql, [list(range(101))])
    assert http.sent == [], "nothing should reach the wire once the row is known unsendable"


def test_d1_executemany_rejects_ragged_rows():
    http = _RecordingHttp()
    db = D1Backend(base_url="http://d1.internal", http=http)

    with pytest.raises(ValueError, match=r"row 0 has 3 values but row 2 has 2"):
        db.executemany("INSERT INTO t (a, b, c) VALUES (?,?,?)", [[1, 2, 3], [4, 5, 6], [7, 8]])
    assert http.sent == []


def test_d1_executemany_rejects_rows_with_no_bound_values():
    http = _RecordingHttp()
    db = D1Backend(base_url="http://d1.internal", http=http)

    with pytest.raises(ValueError, match="no bound values"):
        db.executemany("INSERT INTO t DEFAULT VALUES", [[], []])
    assert http.sent == []


def test_d1_max_rows_per_insert_is_an_upper_bound_not_an_override():
    # The caller's ceiling can only make chunks smaller; it can never push a
    # statement back over D1's parameter cap.
    http = _RecordingHttp()
    rows = [[f"v{r}-{c}" for c in range(13)] for r in range(6)]

    D1Backend(base_url="http://d1.internal", http=http, max_rows_per_insert=2).executemany(_WET_DOC_CHUNKS_SQL, rows)

    assert [len(params) for _, _, params in http.sent] == [26, 26, 26]


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
            return (200, json.dumps({"results": [{"results": []}, {"results": []}]}).encode())

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


def test_d1_batch_parses_worker_dict_envelope():
    # worker thật trả Response.json({ results }) -> dict, KHÔNG phải array.
    class Http:
        def request(self, method, url, data=None, headers=None):
            assert url == "http://d1.internal/batch"
            return (200, json.dumps({"results": [{"results": [{"n": 1}]}]}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    assert db.batch([{"sql": "SELECT 1", "params": []}]) == [{"results": [{"n": 1}]}]


def test_d1_batch_empty_makes_no_request():
    class Http:
        def request(self, *a, **k):
            raise AssertionError("no request for an empty batch")

    assert D1Backend(base_url="http://d1.internal", http=Http()).batch([]) == []


def test_d1_batch_raises_on_http_error():
    class Http:
        def request(self, *a, **k):
            return (500, b"")

    with pytest.raises(RuntimeError, match="D1Backend batch failed"):
        D1Backend(base_url="http://d1.internal", http=Http()).batch([{"sql": "SELECT 1", "params": []}])


def test_d1_executescript_sends_one_batched_request():
    calls = []

    class Http:
        def request(self, method, url, data=None, headers=None):
            calls.append((url, json.loads(data.decode())))
            return (200, json.dumps({"results": []}).encode())

    db = D1Backend(base_url="http://d1.internal", http=Http())
    db.executescript("CREATE TABLE t1 (id INT); CREATE INDEX i1 ON t1 (id);  ;  ")
    assert len(calls) == 1  # 1 request, không phải 1 request mỗi câu lệnh
    assert calls[0][0] == "http://d1.internal/batch"
    assert [q["sql"] for q in calls[0][1]] == ["CREATE TABLE t1 (id INT)", "CREATE INDEX i1 ON t1 (id)"]


def test_d1_backend_from_env(monkeypatch):
    monkeypatch.setenv("MCP_D1_BASE_URL", "http://d1.internal")
    monkeypatch.setenv("MCP_D1_TOKEN", "test-token")

    db = d1_backend_from_env()
    assert db.base_url == "http://d1.internal"
    assert db._token == "test-token"
