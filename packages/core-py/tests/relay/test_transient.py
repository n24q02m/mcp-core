from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest
from starlette.testclient import TestClient
from mcp_core.relay.transient import _build_relay_app


@pytest.mark.asyncio
async def test_submit_triggers_shutdown_event() -> None:
    shutdown_event = threading.Event()
    captured_creds: dict[str, Any] | None = None

    def on_save(server_name: str, creds: dict[str, Any]) -> None:
        nonlocal captured_creds
        captured_creds = creds

    app = _build_relay_app(
        server_name="test-server",
        expected_token="test-token",
        on_save=on_save,
        shutdown_event=shutdown_event,
    )

    # TestClient doesn't automatically run background tasks if we don't
    # use it in a way that allows the event loop to run.
    # However, Starlette's TestClient usually runs the app in the current loop.
    # The issue might be that create_task is called but the loop doesn't
    # advance enough for it to finish.

    with TestClient(app) as client:
        # Authorized
        resp = client.post(
            "/setup/submit",
            headers={"Authorization": "Bearer test-token"},
            json={"api_key": "secret-key"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"status": "saved"}
        assert captured_creds == {"api_key": "secret-key"}

        # Wait for the background task to run.
        # Since we are in an async test, we can use asyncio.sleep.
        # We need to give some time for the background task to start and sleep.
        for _ in range(20):
            if shutdown_event.is_set():
                break
            await asyncio.sleep(0.1)

    assert shutdown_event.is_set()
