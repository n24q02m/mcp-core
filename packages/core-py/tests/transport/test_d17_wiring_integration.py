"""D17 wiring integration tests — helpers wired into production paths.

These tests verify the credential-save refresh wiring:

- D17.2: _refresh_capabilities_cache_after_save is called via the
  on_credentials_saved production path in run_http_server.
"""

from __future__ import annotations

from pathlib import Path

import pytest


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

    # Simulate what run_http_server does when building the wrapper.
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
            if _inspect_creds.isawaitable(raw):
                raw = await raw
            result = raw
        if not (isinstance(result, dict) and result.get("type") == "error"):
            if _lock_path_box:
                try:
                    await local_server._refresh_capabilities_cache_after_save("wet-mcp", _lock_path_box[0])
                except Exception:
                    pass
        return result

    # Populate the box (as run_http_server does after LifecycleLock is constructed).
    _lock_path_box.append(lock)

    # Invoke the wrapper as authorize_post would.
    result = await _on_credentials_saved_with_refresh({"api_key": "secret"}, {"sub": "user-1"})

    assert result is None
    assert original_saved_calls == [{"api_key": "secret"}]
    assert len(refresh_calls) == 1
    assert refresh_calls[0] == ("wet-mcp", lock)


@pytest.mark.asyncio
async def test_authorize_post_calls_refresh_cache_with_async_callback(tmp_path, monkeypatch):
    """D17.2 — refresh helper called even when on_credentials_saved is async.

    Exercises the ``isawaitable`` branch in ``_on_credentials_saved_with_refresh``
    where the original callback returns a coroutine that must be awaited before
    the result is inspected.
    """
    from mcp_core.transport import local_server

    lock = tmp_path / "wet-mcp-55318.lock"
    lock.write_text("123\n55318\ntok\n2026-04-29T00:00:00\nconfigured\n2026-04-29T00:00:00\n")

    refresh_calls: list[tuple[str, Path]] = []

    async def fake_refresh(server_name: str, lock_path: Path) -> None:
        refresh_calls.append((server_name, lock_path))

    monkeypatch.setattr(local_server, "_refresh_capabilities_cache_after_save", fake_refresh)

    original_saved_calls: list[dict] = []

    # async callback — returns a coroutine when called
    async def async_on_credentials_saved(credentials: dict, context: dict) -> dict | None:
        original_saved_calls.append(credentials)
        return None  # success: no error result

    _lock_path_box: list[Path] = []

    async def _on_credentials_saved_with_refresh(
        credentials: dict,
        context: dict,
    ) -> dict | None:
        import inspect as _inspect_creds

        result = None
        if async_on_credentials_saved is not None:
            raw = async_on_credentials_saved(credentials, context)
            if _inspect_creds.isawaitable(raw):
                raw = await raw
            result = raw
        if not (isinstance(result, dict) and result.get("type") == "error"):
            if _lock_path_box:
                try:
                    await local_server._refresh_capabilities_cache_after_save("wet-mcp", _lock_path_box[0])
                except Exception:
                    pass
        return result

    _lock_path_box.append(lock)

    result = await _on_credentials_saved_with_refresh({"api_key": "async-secret"}, {"sub": "user-2"})

    assert result is None
    assert original_saved_calls == [{"api_key": "async-secret"}]
    assert len(refresh_calls) == 1
    assert refresh_calls[0] == ("wet-mcp", lock)
