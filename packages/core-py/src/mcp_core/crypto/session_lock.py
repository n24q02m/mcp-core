"""File-based session lock to prevent duplicate relay sessions.

When multiple MCP server processes start simultaneously (common in Claude Code),
this lock prevents each from creating a separate relay session (rate limit:
max 10 sessions/IP/10min).

Lock file location: <config_dir>/mcp/relay-session-<server>.lock
"""

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_config_dir

logger = logging.getLogger(__name__)

_CONFIG_DIR = Path(user_config_dir("mcp", appauthor=False))
_DEFAULT_MAX_AGE_S = 600.0

# Allow overriding lock directory for testing
_lock_dir_override: str | None = None


def set_lock_dir(path: str | None) -> None:
    """Override lock directory (for testing). Pass None to reset."""
    global _lock_dir_override
    _lock_dir_override = path


def _get_lock_dir() -> Path:
    if _lock_dir_override is not None:
        return Path(_lock_dir_override)
    return _CONFIG_DIR


def _lock_path(server_name: str) -> Path:
    return _get_lock_dir() / f"relay-session-{server_name}.lock"


@dataclass
class SessionInfo:
    """Information about an active relay session."""

    session_id: str
    relay_url: str
    created_at: float


async def acquire_session_lock(
    server_name: str,
    max_age_s: float = _DEFAULT_MAX_AGE_S,
) -> SessionInfo | None:
    """Try to acquire or reuse an existing session lock.

    Returns existing SessionInfo if lock exists and is fresh (< max_age_s old).
    Returns None if no valid lock exists (caller should create new session).
    Uses atomic file operations for safety.

    Args:
        server_name: Server identifier.
        max_age_s: Maximum age of a valid lock in seconds.

    Returns:
        SessionInfo if a valid lock exists, None otherwise.
    """
    path = _lock_path(server_name)
    try:
        if not path.exists():
            return None

        data = json.loads(path.read_text(encoding="utf-8"))
        info = SessionInfo(
            session_id=data["session_id"],
            relay_url=data["relay_url"],
            created_at=data["created_at"],
        )

        age = time.time() - info.created_at
        if age > max_age_s:
            logger.debug(
                "Session lock for %s expired (age=%.1fs > max=%.1fs)",
                server_name,
                age,
                max_age_s,
            )
            # Expired lock: clean up and return None
            await release_session_lock(server_name)
            return None

        logger.debug(
            "Reusing session lock for %s (age=%.1fs)",
            server_name,
            age,
        )
        return info

    except (json.JSONDecodeError, KeyError, OSError) as err:
        logger.debug("Invalid session lock for %s: %s", server_name, err)
        # Corrupt lock file: clean up and return None
        try:
            await release_session_lock(server_name)
        except OSError:
            pass
        return None


async def write_session_lock(server_name: str, info: SessionInfo) -> None:
    """Write session info to lock file after creating a new relay session.

    Args:
        server_name: Server identifier.
        info: Session information to persist.
    """
    path = _lock_path(server_name)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "session_id": info.session_id,
        "relay_url": info.relay_url,
        "created_at": info.created_at,
    }

    # Write atomically via temp file + rename
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(data), encoding="utf-8")
    tmp_path.replace(path)

    logger.debug("Wrote session lock for %s", server_name)


async def release_session_lock(server_name: str) -> None:
    """Remove the lock file (call when session completes or is abandoned).

    Args:
        server_name: Server identifier.
    """
    path = _lock_path(server_name)
    try:
        path.unlink(missing_ok=True)
        logger.debug("Released session lock for %s", server_name)
    except OSError as err:
        logger.debug("Failed to release session lock for %s: %s", server_name, err)
