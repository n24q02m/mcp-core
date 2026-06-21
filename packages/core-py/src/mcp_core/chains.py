"""Capability provider-chain primitives (shared across MCP servers).

A *capability* (search, embedding, rerank, browser, ...) is resolved the same
way everywhere: an ordered chain of cloud providers (vendor API + key), an
optional self-host/local leg, and a per-capability "disable-local" toggle. This
module owns the two pieces of that shape which are identical across every server
and capability:

  * :func:`resolve_backend` — the 3-way decision (cloud / local / unavailable)
    that replaces the old "non-empty chain => cloud, else local" conflation. The
    old rule made disabling the heavy local leg (the ONNX download, the bundled
    chromium, the auto-local SearXNG) impossible without also pinning a specific
    cloud provider.
  * :func:`run_with_fallback` — runtime fallback for capabilities that do their
    own dispatch (search, browser): try each provider in order, advance on error
    or empty result, return the first non-empty. (Embedding/rerank delegate
    fallback to litellm's own model-chain, so they only need
    :func:`resolve_backend`.)

The per-capability "disable-local" env name (``DISABLE_LOCAL_SEARCH`` /
``DISABLE_LOCAL_BROWSER`` / ``DISABLE_LOCAL_EMBED`` / ``DISABLE_LOCAL_RERANK``)
is read by :func:`local_enabled_from_env` and passed to :func:`resolve_backend`
as a bool. Capabilities with no local leg (llm, captcha) pass
``has_local_leg=False`` (or ``toggle_env=None``).
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Mapping, Sequence
from enum import StrEnum
from typing import TypeVar

T = TypeVar("T")

# Values that, when set on a DISABLE_LOCAL_<X> env var, turn the local leg OFF.
_TRUTHY = frozenset({"1", "true", "yes", "on"})


class Backend(StrEnum):
    """Resolved backend for a capability.

    A :class:`~enum.StrEnum`, so members compare equal to their string value
    (``resolve_backend(...) == "cloud"`` works) and existing string-typed
    callers keep working while new callers can use the enum directly.
    """

    CLOUD = "cloud"
    LOCAL = "local"
    UNAVAILABLE = "unavailable"


def local_enabled_from_env(
    toggle_env: str | None,
    *,
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Whether the local leg of a capability is enabled.

    ``toggle_env`` is the capability's ``DISABLE_LOCAL_<X>`` env var name. A
    truthy value (``1`` / ``true`` / ``yes`` / ``on``, case-insensitive)
    DISABLES the local leg, so this returns ``False``. Absent / empty / any
    other value -> the local leg stays enabled (``True``). ``toggle_env=None``
    means "this capability has no disable-local switch" and always returns
    ``True`` (the caller still gates on ``has_local_leg`` in
    :func:`resolve_backend`).
    """
    if toggle_env is None:
        return True
    env = os.environ if environ is None else environ
    raw = env.get(toggle_env, "")
    return raw.strip().lower() not in _TRUTHY


def resolve_backend(
    *,
    has_cloud_chain: bool,
    local_enabled: bool,
    has_local_leg: bool = True,
) -> Backend:
    """3-way capability resolution.

    * :attr:`Backend.CLOUD` — a usable cloud provider chain is configured.
    * :attr:`Backend.LOCAL` — no cloud chain, but the local leg exists and is
      enabled.
    * :attr:`Backend.UNAVAILABLE` — no cloud chain and the local leg is absent
      or disabled.

    This is the single rule every server + capability shares. It deliberately
    separates "is the local leg on?" (``local_enabled``) from "is a cloud chain
    configured?" (``has_cloud_chain``) so a deployment can run cloud-only by
    disabling local WITHOUT being forced to pin a particular cloud model — the
    conflation that ``"cloud" if chain else "local"`` could not express.
    """
    if has_cloud_chain:
        return Backend.CLOUD
    if has_local_leg and local_enabled:
        return Backend.LOCAL
    return Backend.UNAVAILABLE


async def run_with_fallback(
    providers: Sequence[Callable[[], Awaitable[T]]],
    *,
    is_empty: Callable[[T], bool] | None = None,
    on_error: Callable[[int, Exception], None] | None = None,
) -> T | None:
    """Try each provider thunk in order; return the first non-empty result.

    Advances to the next provider when a thunk raises OR returns an "empty"
    result (per ``is_empty``; default: falsey, which covers ``[]`` / ``""`` /
    ``None``). Returns ``None`` when every provider is exhausted without a
    non-empty result.

    ``on_error(index, exc)`` is invoked for each provider that raises (intended
    for the caller's logging) and MUST NOT raise itself. This is the runtime
    fallback for capabilities — search, browser — that dispatch their own
    backends; embedding/rerank rely on litellm's internal model-chain fallback
    instead and never call this.
    """
    empty = is_empty if is_empty is not None else (lambda r: not r)
    for idx, provider in enumerate(providers):
        try:
            result = await provider()
        except Exception as exc:  # noqa: BLE001 - fallback advances past any provider error
            if on_error is not None:
                on_error(idx, exc)
            continue
        if not empty(result):
            return result
    return None
