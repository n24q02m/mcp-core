"""Single active form session token state — D11.

Prevents racing 2+ Claude Code sessions concurrently filling the relay form
for the same server. Only one bridge holds the active form session at a time;
subsequent claim_session() calls return the existing session info without
issuing a new token.
"""

from __future__ import annotations

import secrets
from mcp_core.crypto.timing import timing_safe_equal
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

SESSION_TTL = timedelta(minutes=30)
TOKEN_NBYTES = 32


@dataclass
class ActiveFormSession:
    token: str
    client_id: str
    started_at: datetime
    expires_at: datetime


_state: Optional[ActiveFormSession] = None
_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def claim_session(client_id: str) -> ActiveFormSession:
    """Claim form session. If active and unexpired, return existing.
    Otherwise mint a new session bound to client_id."""
    global _state
    with _lock:
        if _state is not None and _state.expires_at > _now():
            return _state
        now = _now()
        _state = ActiveFormSession(
            token=secrets.token_urlsafe(TOKEN_NBYTES),
            client_id=client_id,
            started_at=now,
            expires_at=now + SESSION_TTL,
        )
        return _state


def release_session() -> None:
    """Clear active session (called after submit success or expire)."""
    global _state
    with _lock:
        _state = None


def is_session_active() -> bool:
    """Return True if there's an active unexpired session."""
    global _state
    with _lock:
        if _state is None:
            return False
        if _state.expires_at <= _now():
            _state = None
            return False
        return True


def validate_session_token(token: str) -> bool:
    """Validate token against active session. Returns False if no active or mismatch."""
    global _state
    with _lock:
        if _state is None:
            return False
        if _state.expires_at <= _now():
            _state = None
            return False
        return timing_safe_equal(_state.token, token)


def get_active_session() -> Optional[ActiveFormSession]:
    """Return active session info or None. Used by config__open_relay tool."""
    global _state
    with _lock:
        if _state is None:
            return None
        if _state.expires_at <= _now():
            _state = None
            return None
        return _state
