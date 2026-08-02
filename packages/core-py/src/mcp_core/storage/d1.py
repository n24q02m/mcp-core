"""HTTP client for Cloudflare D1 via the Worker outbound-handler (or REST fallback).

Wire contract (matches src/worker.ts):
POST {base}/query with JSON {"sql": str, "params": list} -> 200 {"results": [<row dicts>]}.
POST {base}/batch with JSON array [{"sql": str, "params": list}, ...] -> 200 {"results": [...]}
(a dict envelope wrapping the per-statement results, NOT an array -- this was
previously documented wrong here for a long time because executemany's batch
path only checked the HTTP status code and never read the response body, so
the shape mismatch never surfaced).
Prepared statements only (sql + bound params); raw SQL text is never sent.
Fail-loud: any non-200 raises (no silent empty results).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx

# Cloudflare D1 rejects any query carrying more than this many bound parameters
# ("Maximum bound parameters per query: 100"), and the cap applies to each
# statement inside a /batch too. It counts PARAMETERS, not rows: rows per
# multi-row INSERT must therefore be DERIVED by dividing this by the column
# count, never assumed. A wide table blows the cap long before the row count
# looks large -- wet's 13-column doc_chunks INSERT is already over at 8 rows
# (8 x 13 = 104), and a 100-row chunk of it sends 1300.
# https://developers.cloudflare.com/d1/platform/limits/
D1_MAX_BOUND_PARAMS = 100

# Statements per executescript /batch POST. Unrelated to the parameter cap --
# migration statements bind nothing -- this only keeps one request body from
# growing without bound.
_STATEMENTS_PER_SCRIPT_BATCH = 100

# Matches the trailing VALUES (?,?,...) tuple of a single-row INSERT so it can
# be expanded into a multi-row INSERT for chunked batches.
_VALUES_TUPLE_RE = re.compile(r"VALUES\s*(\([^)]*\))\s*$", re.IGNORECASE)


def _validate_row_width(rows: list[list[Any]]) -> int:
    """Return the bound parameters per row, or raise saying why they cannot be sent.

    Three deliberate rejections, all of which D1 would otherwise answer with a
    bare ``HTTP 400`` that names neither the table nor the number that broke:

    * **No bound values.** A row must bind at least one parameter -- there is
      nothing to divide the cap by, and a multi-row INSERT of empty tuples is
      not expressible. (``rows`` being empty at all is not an error;
      :meth:`D1Backend.executemany` returns before reaching here.)
    * **Ragged rows.** The multi-row INSERT repeats one ``?``-tuple, so a row of
      a different width would misalign every value after it against the columns.
    * **Wider than the cap.** Past ``D1_MAX_BOUND_PARAMS`` columns not even a
      single row fits in one statement, so no chunk size can rescue it.
    """
    n_cols = len(rows[0])
    if n_cols == 0:
        raise ValueError(
            "D1Backend.executemany got rows with no bound values; each row must "
            "carry at least one parameter to bind to the VALUES (?) tuple."
        )
    ragged = next((i for i, row in enumerate(rows) if len(row) != n_cols), None)
    if ragged is not None:
        raise ValueError(
            f"D1Backend.executemany got ragged rows: row 0 has {n_cols} values "
            f"but row {ragged} has {len(rows[ragged])}. Every row must bind the "
            "same columns, in the same order."
        )
    if n_cols > D1_MAX_BOUND_PARAMS:
        raise ValueError(
            f"D1Backend.executemany cannot send a row of {n_cols} columns: one "
            f"row alone needs {n_cols} bound parameters and Cloudflare D1 caps a "
            f"query at {D1_MAX_BOUND_PARAMS}. Narrow the table or split the "
            "INSERT across several statements."
        )
    return n_cols


class _HttpxHttp:
    def request(self, method, url, data=None, headers=None):
        resp = httpx.request(method, url, content=data, headers=headers or {}, timeout=30.0)
        return (resp.status_code, resp.content)


class D1Backend:
    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        http=None,
        # An upper bound layered ON TOP of the parameter-derived chunk size, not
        # a replacement for it: executemany takes the smaller of the two, so a
        # caller can shrink chunks but can never push a statement past D1's cap.
        # The default is the loosest value that can ever bind -- reachable only
        # by a one-column table, where 100 rows is exactly 100 parameters.
        max_rows_per_insert: int = D1_MAX_BOUND_PARAMS,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._http = http or _HttpxHttp()
        self.max_rows_per_insert = max_rows_per_insert

    def _headers(self) -> dict:
        if self._token:
            return {
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            }
        return {"Content-Type": "application/json"}

    def execute(self, sql: str, params: list[Any]) -> list[dict]:
        body = json.dumps({"sql": sql, "params": params}).encode()
        status, data = self._http.request("POST", f"{self.base_url}/query", body, self._headers())
        if status != 200:
            raise RuntimeError(f"D1Backend query failed: HTTP {status}")
        return json.loads(data.decode()).get("results", [])

    def batch(self, queries: list[dict[str, Any]]) -> list:
        # POST {base}/batch -> Response.json({ results: batchResults }), i.e. a
        # dict envelope (NOT an array) even though it wraps multiple statements.
        if not queries:
            return []
        body = json.dumps(queries).encode()
        status, data = self._http.request("POST", f"{self.base_url}/batch", body, self._headers())
        if status != 200:
            raise RuntimeError(f"D1Backend batch failed: HTTP {status}")
        return json.loads(data.decode()).get("results", [])

    def fetchall(self, sql: str, params: list[Any]) -> list[dict]:
        return self.execute(sql, params)

    def fetchone(self, sql: str, params: list[Any]) -> dict | None:
        rows = self.execute(sql, params)
        return rows[0] if rows else None

    def executemany(self, sql: str, rows: list[list[Any]]) -> None:
        # D1 has no native executemany over HTTP; batch rows into multi-row
        # INSERTs (one POST per chunk) by expanding the VALUES (...) tuple.
        # Chunk size comes from D1's bound-parameter cap divided by the row
        # width, so a wide table simply yields fewer rows per statement.
        if not rows:
            return
        n_cols = _validate_row_width(rows)
        rows_per_stmt = min(self.max_rows_per_insert, D1_MAX_BOUND_PARAMS // n_cols)
        match = _VALUES_TUPLE_RE.search(sql)
        for i in range(0, len(rows), rows_per_stmt):
            batch = rows[i : i + rows_per_stmt]
            if match and len(batch) > 1:
                tuple_sql = match.group(1)
                # ⚡ Bolt: Use list multiplication instead of generator expression for faster string joining in hot path
                values = ", ".join([tuple_sql] * len(batch))
                batched_sql = sql[: match.start(1)] + values
                flat = [v for row in batch for v in row]
                # batched_sql only expands the ?-placeholder VALUES tuple; row
                # data is bound via `flat` params, never interpolated -> safe.
                # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
                self.execute(batched_sql, flat)
            else:
                # ⚡ Bolt: Use the /batch endpoint for non-INSERT batched statements (or when SQL-rewriting fails)
                # to avoid the N+1 query problem of making a separate HTTP request for each row in the batch.
                self.batch([{"sql": sql, "params": row} for row in batch])

    def executescript(self, sql: str) -> None:
        # Migrations: split on ';' and run in /batch chunks (one POST per
        # chunk) instead of one request per statement.
        stmts = [s.strip() for s in sql.split(";") if s.strip()]
        for i in range(0, len(stmts), _STATEMENTS_PER_SCRIPT_BATCH):
            chunk = stmts[i : i + _STATEMENTS_PER_SCRIPT_BATCH]
            self.batch([{"sql": stmt, "params": []} for stmt in chunk])


def d1_backend_from_env() -> D1Backend:
    base = os.environ.get("MCP_D1_BASE_URL", "http://d1.internal")
    return D1Backend(base_url=base, token=os.environ.get("MCP_D1_TOKEN"))


__all__ = ["D1Backend", "d1_backend_from_env"]
