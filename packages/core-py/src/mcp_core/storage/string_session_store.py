"""KV-persisted Telethon StringSession seam with save-on-change.

Two pieces, used together by a serverless Telegram MCP:

``StringSessionStore``
    Wraps :class:`~mcp_core.storage.per_plugin_store.PerPluginStore` (sub_key
    ``"session"``) to persist the Telethon session string as an encrypted blob
    in whatever credential backend is configured (LocalFs / CfKv / InMemory).
    It depends ONLY on PerPluginStore and never imports telethon.

``SaveOnChangeStringSession``
    A telethon ``StringSession`` subclass whose ``save()`` pushes the serialized
    string to a ``sink`` callback. Telethon mutates the session in place during a
    login flow and calls ``save()`` when auth state changes; the sink lets the
    caller persist that string (e.g. into ``StringSessionStore``) on every change
    without a polling loop.

Telethon import gating
    telethon is heavy and is a Telegram-only dependency. mcp-core is imported by
    many servers (wet/imagine/mnemo) that do NOT install telethon, and
    ``mcp_core.storage.__init__`` eagerly re-exports the names below. So the
    telethon import is GATED in a try/except: this module imports cleanly without
    telethon, and ``SaveOnChangeStringSession`` falls back to subclassing
    ``object`` (it is unusable without telethon, but merely importing the module
    — and thus ``import mcp_core.storage`` — does not break). telethon lives in
    core-py's dev dependency group only, never in ``[project].dependencies``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Optional

from mcp_core.storage.backends import CredentialBackend
from mcp_core.storage.per_plugin_store import PerPluginStore

if TYPE_CHECKING:
    from telethon.sessions import StringSession as _StringSessionBase
else:
    try:
        from telethon.sessions import StringSession as _StringSessionBase
    except ImportError:  # pragma: no cover - telethon is a telegram-only dep
        _StringSessionBase = object

_HAS_TELETHON = _StringSessionBase is not object


class StringSessionStore:
    """Encrypted KV store for a single Telethon session string.

    Persists ``{"session": session_str}`` under the ``"session"`` sub_key via
    PerPluginStore, so the layout, encryption, and multi-user key derivation are
    shared with every other per-plugin credential. Does not import telethon.
    """

    def __init__(
        self,
        plugin_name: str,
        sub: Optional[str] = None,
        backend: Optional[CredentialBackend] = None,
    ) -> None:
        self._store = PerPluginStore(plugin_name, sub, backend=backend, sub_key="session")

    def load(self) -> Optional[str]:
        """Return the stored session string, or None when absent/undecryptable."""
        payload = self._store.load()
        if not payload:
            return None
        return payload.get("session")

    def save(self, session_str: str) -> None:
        """Persist the session string as ``{"session": session_str}``."""
        self._store.save({"session": session_str})

    def clear(self) -> None:
        """Delete the stored session blob."""
        self._store.clear()


class SaveOnChangeStringSession(_StringSessionBase):
    """Telethon StringSession that pushes its serialized string to a sink on save.

    Telethon calls ``save()`` whenever the session's auth state changes; setting
    a ``sink`` lets the caller persist the new string immediately (no polling).
    Requires telethon — the gated base class above is ``object`` only so that
    importing this module without telethon does not fail.
    """

    def __init__(
        self,
        session_str: Optional[str] = None,
        sink: Optional[Callable[[str], None]] = None,
    ) -> None:
        if session_str is None:
            super().__init__()
        else:
            super().__init__(session_str)
        self._sink = sink

    def save(self) -> str:
        result = super().save()
        if self._sink is not None:
            self._sink(result)
        return result
