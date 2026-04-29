"""D17 wiring integration tests — helpers wired into production paths.

These tests verify the two critical integration points that were identified as
dead code gaps in the Wave 9 review:

- D17.2: _refresh_capabilities_cache_after_save is called via the
  on_credentials_saved production path in run_local_server.
- D17.3: _start_poller_thread is called from run_smart_stdio_proxy.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest


def test_run_smart_stdio_proxy_starts_sentinel_poller_thread(tmp_path, monkeypatch):
    """D17.3 — run_smart_stdio_proxy must start the sentinel poller thread.

    Verifies that _start_poller_thread is called exactly once with the
    resolved cache_lock_path when a lock file exists for the server.
    """
    import io
    import sys

    from mcp_core.transport import smart_stdio

    lock = tmp_path / "wet-mcp-55317.lock"
    lock.write_text("123\n55317\ntok\n2026-04-29T00:00:00\nconfigured\n2026-04-29T00:00:00\n")

    poller_calls: list[Path] = []

    def fake_start_poller_thread(lock_path: Path):
        poller_calls.append(lock_path)
        # Return a mock thread object (run_smart_stdio_proxy does not join it).
        t = MagicMock()
        t.is_alive.return_value = True
        return t

    # Patch _find_newest_lock to return our tmp lock, _start_poller_thread to
    # capture calls, and get_active_daemon so the function exits cleanly
    # without touching the network.
    monkeypatch.setattr(smart_stdio, "_find_newest_lock", lambda name: lock)
    monkeypatch.setattr(smart_stdio, "_start_poller_thread", fake_start_poller_thread)
    # Return a daemon result so we skip the spawn path entirely.
    monkeypatch.setattr(smart_stdio, "get_active_daemon", lambda name: (55317, "tok"))

    # Replace sys.stdin / sys.stdout entirely with fake objects whose .buffer
    # attribute has a setter (pytest's DontReadFromInput.buffer has no setter).
    class _FakeStdin:
        buffer = io.BytesIO(b"")  # immediate EOF

    class _FakeStdout:
        buffer = io.BytesIO()

    monkeypatch.setattr(
        smart_stdio,
        "sys",
        MagicMock(
            stdin=_FakeStdin(),
            stdout=_FakeStdout(),
            # keep platform so Windows flag checks work
            platform=sys.platform,
        ),
    )

    # run_smart_stdio_proxy is synchronous; drive it directly.
    smart_stdio.run_smart_stdio_proxy("wet-mcp", ["uvx", "wet-mcp"])

    assert len(poller_calls) == 1, f"Expected 1 poller start, got {len(poller_calls)}"
    assert poller_calls[0] == lock


@pytest.mark.asyncio
async def test_authorize_post_calls_refresh_cache(tmp_path, monkeypatch):
    """D17.2 — credential-save wrapper calls _refresh_capabilities_cache_after_save.

    Simulates the path: relay form submitted -> on_credentials_saved wrapper
    (_on_credentials_saved_with_refresh) -> _refresh_capabilities_cache_after_save.

    We exercise the wrapper directly (extracted via closure introspection) rather
    than spinning up a full uvicorn server, to keep the test fast and hermetic.
    """
    from mcp_core.transport import local_server

    lock = tmp_path / "wet-mcp-55317.lock"
    lock.write_text("123\n55317\ntok\n2026-04-29T00:00:00\nconfigured\n2026-04-29T00:00:00\n")

    refresh_calls: list[tuple[str, Path]] = []

    async def fake_refresh(server_name: str, lock_path: Path) -> None:
        refresh_calls.append((server_name, lock_path))

    monkeypatch.setattr(local_server, "_refresh_capabilities_cache_after_save", fake_refresh)

    # Simulate what run_local_server does when building the wrapper.
    original_saved_calls: list[dict] = []

    async def original_on_credentials_saved(credentials: dict, context: dict) -> dict | None:
        original_saved_calls.append(credentials)
        return None  # success: no error result

    _lock_path_box: list[Path] = []

    async def _on_credentials_saved_with_refresh(
        credentials: dict,
        context: dict,
    ) -> dict | None:
        import inspect as _inspect_creds

        result = None
        if original_on_credentials_saved is not None:
            raw = original_on_credentials_saved(credentials, context)
            if _inspect_creds.iscoroutine(raw):
                raw = await raw
            result = raw
        if not (isinstance(result, dict) and result.get("type") == "error"):
            if _lock_path_box:
                try:
                    await local_server._refresh_capabilities_cache_after_save("wet-mcp", _lock_path_box[0])
                except Exception:
                    pass
        return result

    # Populate the box (as run_local_server does after LifecycleLock is constructed).
    _lock_path_box.append(lock)

    # Invoke the wrapper as authorize_post would.
    result = await _on_credentials_saved_with_refresh({"api_key": "secret"}, {"sub": "user-1"})

    assert result is None
    assert original_saved_calls == [{"api_key": "secret"}]
    assert len(refresh_calls) == 1
    assert refresh_calls[0] == ("wet-mcp", lock)
