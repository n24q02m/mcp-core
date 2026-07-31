"""HTTP client for Cloudflare Vectorize v2 via the Worker outbound-handler.

upsert:      POST {base}/upsert (ndjson lines {id, values, metadata}) -> {"mutationId": ...}
query:       POST {base}/query json {vector, topK, filter} -> {"matches": [{id, score, metadata}]}
deleteByIds: POST {base}/deleteByIds json {"ids": [...]} -> {"mutationId": ...}
ready:       GET  {base} -> {"ready": bool}
Every route returns the Vectorize binding's own result verbatim -- unlike the D1
handler's /batch, none of these wrap it in an envelope.
Upsert is eventual (~seconds); add_chunks() callers must wait_until_indexed()
before asserting search results. Fail-loud on non-200.
"""

from __future__ import annotations

import json
import logging
import os
import time

import httpx

logger = logging.getLogger(__name__)

# Vectorize returns at most this many matches once values/metadata are requested.
_MAX_TOP_K = 50


class _HttpxHttp:
    def request(self, method, url, data=None, headers=None):
        resp = httpx.request(method, url, content=data, headers=headers or {}, timeout=30.0)
        return (resp.status_code, resp.content)


class VectorizeBackend:
    def __init__(self, base_url: str, idx: str, token: str | None = None, http=None) -> None:
        self.base_url = base_url.rstrip("/")
        self.idx = idx
        self._token = token
        self._http = http or _HttpxHttp()
        self._warned_top_k_clamp = False

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    def upsert(self, vectors: list[dict]) -> str:
        ndjson = "\n".join([json.dumps(v) for v in vectors]).encode()
        status, data = self._http.request("POST", f"{self.base_url}/upsert", ndjson, self._headers())
        if status != 200:
            raise RuntimeError(f"VectorizeBackend upsert failed: HTTP {status}")
        return json.loads(data.decode()).get("mutationId", "")

    def delete_by_ids(self, ids: list[str]) -> str:
        # POST {base}/deleteByIds -> Response.json(await env.VECTORIZE.deleteByIds(ids)),
        # i.e. the binding's {"mutationId": ...} straight through.
        if not ids:
            return ""
        body = json.dumps({"ids": ids}).encode()
        status, data = self._http.request("POST", f"{self.base_url}/deleteByIds", body, self._headers())
        if status != 200:
            raise RuntimeError(f"VectorizeBackend delete_by_ids failed: HTTP {status}")
        return json.loads(data.decode()).get("mutationId", "")

    def query(self, vector: list[float], top_k: int, metadata_filter: dict | None = None) -> list[dict]:
        if top_k > _MAX_TOP_K:
            # Say it once per instance, not once per call: the ceiling belongs to
            # the index, so a search loop would repeat the same line forever. The
            # caller asked for more results than it can possibly receive, and
            # silently handing back a short list is indistinguishable from the
            # index genuinely holding that few.
            if not self._warned_top_k_clamp:
                logger.warning(
                    "VectorizeBackend[%s]: top_k=%d clamped to %d (Vectorize returns at most %d "
                    "matches with values/metadata); further clamps on this instance are not logged",
                    self.idx,
                    top_k,
                    _MAX_TOP_K,
                    _MAX_TOP_K,
                )
                self._warned_top_k_clamp = True
            top_k = _MAX_TOP_K
        body = json.dumps({"vector": vector, "topK": top_k, "filter": metadata_filter or {}}).encode()
        status, data = self._http.request("POST", f"{self.base_url}/query", body, self._headers())
        if status != 200:
            raise RuntimeError(f"VectorizeBackend query failed: HTTP {status}")
        return json.loads(data.decode()).get("matches", [])

    def wait_until_indexed(self, poll_interval: float = 1.0, max_wait: float = 30.0) -> bool:
        deadline = time.monotonic() + max_wait
        while time.monotonic() <= deadline:
            status, data = self._http.request("GET", self.base_url, None, self._headers())
            if status == 200 and json.loads(data.decode()).get("ready"):
                return True
            if poll_interval:
                time.sleep(poll_interval)
        return False


def vectorize_backend_from_env() -> VectorizeBackend:
    base = os.environ.get("MCP_VECTORIZE_BASE_URL", "http://vectorize.internal")
    idx = os.environ["MCP_VECTORIZE_IDX"]  # required when DOCS_DB_BACKEND=cf-d1
    return VectorizeBackend(base_url=base, idx=idx, token=os.environ.get("MCP_VECTORIZE_TOKEN"))


__all__ = ["VectorizeBackend", "vectorize_backend_from_env"]
