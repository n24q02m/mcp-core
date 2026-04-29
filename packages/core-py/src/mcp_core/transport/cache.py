"""Tools-list cache with version-aware key (D10).

Cache filename: ``<server>-<port>-<srv_version>-<core_version>.tools.json``.
A mismatch on either ``srv_version`` (the upstream MCP server's version) or
``core_version`` (mcp-core itself) invalidates the cache, so an upgrade on
either side never serves a stale tool surface.

Persist uses an atomic ``.tmp`` + ``os.replace`` rename (Windows-safe). All
errors during persist are logged + suppressed: a flaky filesystem must never
crash the transparent bridge. This is the D10 root-cause fix for
``Failed to persist capabilities cache`` hard-failures (crg #384).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _cache_dir() -> Path:
    return Path.home() / ".config" / "mcp" / "cache"


def cache_filename(server_name: str, port: int, srv_version: str, core_version: str) -> str:
    return f"{server_name}-{port}-{srv_version}-{core_version}.tools.json"


def _atomic_write(path: Path, content: str) -> None:
    """Atomic write via .tmp + os.replace (Windows-safe)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def persist_tools_cache(
    server_name: str,
    port: int,
    srv_version: str,
    core_version: str,
    tools: list[dict[str, Any]],
) -> None:
    """Persist tools list. Errors logged + suppressed (D10 fixes #384)."""
    name = cache_filename(server_name, port, srv_version, core_version)
    path = _cache_dir() / name
    payload = json.dumps({"tools": tools, "srv_version": srv_version, "core_version": core_version})
    try:
        _atomic_write(path, payload)
    except OSError as exc:
        logger.debug("Failed to persist capabilities cache for %s: %s", server_name, exc)


def load_tools_cache(
    server_name: str,
    port: int,
    srv_version: str,
    core_version: str,
) -> Optional[list[dict[str, Any]]]:
    """Load tools cache; return None on missing or version mismatch."""
    name = cache_filename(server_name, port, srv_version, core_version)
    path = _cache_dir() / name
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("srv_version") != srv_version or payload.get("core_version") != core_version:
        return None
    tools = payload.get("tools")
    if not isinstance(tools, list):
        return None
    return tools
