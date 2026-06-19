"""Key-level rotation: try multiple API keys for ONE provider, advancing only on
a key-specific failure (HTTP 429 rate-limit / 401-403 auth). The layer below the
capability->provider chain; reuses the same fallback semantics."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")

_ROTATABLE_STATUS = {401, 403, 429}
# litellm raises typed errors; match by class name to avoid a hard import here.
_ROTATABLE_NAMES = {"RateLimitError", "AuthenticationError", "PermissionDeniedError"}


def split_keys(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [k.strip() for k in raw.split(",") if k.strip()]


def is_rotatable_error(exc: BaseException) -> bool:
    status = getattr(exc, "status_code", None)
    if isinstance(status, int) and status in _ROTATABLE_STATUS:
        return True
    return type(exc).__name__ in _ROTATABLE_NAMES


async def rotate_keys(
    keys: list[str],
    call: Callable[[str], Awaitable[T]],
    *,
    label: str = "provider",
) -> T:
    if len(keys) <= 1:
        return await call(keys[0] if keys else "")
    last: BaseException | None = None
    for key in keys:
        try:
            return await call(key)
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            if not is_rotatable_error(exc):
                raise
            last = exc
    assert last is not None
    raise last
