"""HTTP client for Cloudflare D1 via the Worker outbound-handler (or REST fallback).

Wire contract (matches src/worker.ts): POST {base}/query with JSON
{"sql": str, "params": list} -> 200 {"results": [<row dicts>]}.
Prepared statements only (sql + bound params); raw SQL text is never sent.
Fail-loud: any non-200 raises (no silent empty results).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import httpx

# SQLite bound-variable ceiling; D1 inherits it. Keep INSERT batches well under.
_DEFAULT_MAX_ROWS_PER_INSERT = 100

# Matches a simple VALUES (?,?,...) tuple (only positional placeholders) of a
# single-row INSERT so it can be expanded into a multi-row INSERT for efficiency.
_SIMPLE_VALUES_TUPLE_RE = re.compile(r"VALUES\s*(\(\s*\?\s*(?:,\s*\?\s*)*\))\s*$", re.IGNORECASE)


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
        max_rows_per_insert: int = _DEFAULT_MAX_ROWS_PER_INSERT,
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

    def _call(self, endpoint: str, payload: Any) -> Any:
        body = json.dumps(payload).encode()
        status, data = self._http.request("POST", f"{self.base_url}/{endpoint}", body, self._headers())
        if status != 200:
            raise RuntimeError(f"D1Backend {endpoint} failed: HTTP {status}")
        return json.loads(data.decode())

    def execute(self, sql: str, params: list[Any]) -> list[dict]:
        res = self._call("query", {"sql": sql, "params": params})
        return res.get("results", [])

    def fetchall(self, sql: str, params: list[Any]) -> list[dict]:
        return self.execute(sql, params)

    def fetchone(self, sql: str, params: list[Any]) -> dict | None:
        rows = self.execute(sql, params)
        return rows[0] if rows else None

    def executemany(self, sql: str, rows: list[list[Any]]) -> None:
        # D1 has no native executemany over HTTP. We optimize simple multi-row
        # INSERTs via VALUES expansion, and use /batch for everything else.
        if not rows:
            return
        match = _SIMPLE_VALUES_TUPLE_RE.search(sql)
        for i in range(0, len(rows), self.max_rows_per_insert):
            batch = rows[i : i + self.max_rows_per_insert]
            if match and len(batch) > 1:
                tuple_sql = match.group(1)
                values = ", ".join(tuple_sql for _ in batch)
                batched_sql = sql[: match.start(1)] + values
                flat = [v for row in batch for v in row]
                # ⚡ Bolt: batched_sql only repeats the safe ?-placeholder tuple;
                # row data is bound via 'flat' params, never interpolated.
                # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
                self.execute(batched_sql, flat)
            else:
                # ⚡ Bolt: Use /batch endpoint to resolve N+1 query issues when
                # multi-row VALUES expansion is not applicable.
                self._call("batch", [{"sql": sql, "params": row} for row in batch])

    def executescript(self, sql: str) -> None:
        # Migrations: split on ';' and run each non-empty statement.
        for stmt in (s.strip() for s in sql.split(";")):
            if stmt:
                self.execute(stmt, [])


def d1_backend_from_env() -> D1Backend:
    base = os.environ.get("MCP_D1_BASE_URL", "http://d1.internal")
    return D1Backend(base_url=base, token=os.environ.get("MCP_D1_TOKEN"))


__all__ = ["D1Backend", "d1_backend_from_env"]
