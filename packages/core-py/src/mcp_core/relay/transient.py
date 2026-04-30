"""Transient relay HTTP server for stdio-mode plugins.

When a plugin runs in stdio mode (no long-running daemon), the
``config__open_relay`` tool spawns an in-process HTTP server only when called.
The server self-shutdowns after credentials are submitted, after a 10-minute
idle timeout, or when the plugin process exits.

This is the stdio-mode counterpart to the HTTP-mode persistent ``/setup``
endpoint served by ``mcp_core.transport.local_server.run_http_daemon``. It
intentionally uses Starlette (already a transitive dependency via FastMCP)
rather than FastAPI to avoid pulling a new top-level dependency for a
single-form server.
"""

from __future__ import annotations

import asyncio
import secrets
import socket
import threading
import time
import webbrowser
from collections.abc import Callable
from typing import Any

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route


def _find_free_port() -> int:
    """Ask the kernel for an unused ephemeral port via socket bind to port 0.

    The OS chooses a free port, we read it back from ``getsockname``, then
    immediately close the socket. There is a brief race window before the
    caller binds again, but for a localhost-only one-shot setup form it is
    acceptable.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _generate_token() -> str:
    """Generate a URL-safe random bearer token for relay form auth."""
    return secrets.token_urlsafe(32)


# Form HTML uses ``textContent`` only — no ``innerHTML`` with untrusted
# content. The placeholder ``SERVER_NAME`` is interpolated server-side from a
# value the plugin author controls, so it is safe; everything else is set via
# DOM APIs in the inline script.
_HTML_FORM_TEMPLATE = (
    "<!DOCTYPE html><html><head><title>SERVER_NAME setup</title></head>"
    "<body><h1 id='title'></h1>"
    "<p>Paste a JSON object containing your credentials below, then click "
    "Submit. The form auto-closes after a successful save.</p>"
    "<form id='relayForm'>"
    "<textarea name='json' rows='10' cols='60' "
    "placeholder='{&quot;api_key&quot;: &quot;...&quot;}'></textarea><br>"
    "<button type='submit'>Submit</button>"
    "</form>"
    "<div id='status'></div>"
    "<script>"
    "document.getElementById('title').textContent = 'SERVER_NAME credentials';"
    "document.getElementById('relayForm').onsubmit = async function(e) {"
    "  e.preventDefault();"
    "  var token = new URLSearchParams(window.location.search).get('token');"
    "  var jsonText = e.target.json.value;"
    "  var resp = await fetch('/setup/submit', {"
    "    method: 'POST',"
    "    headers: {"
    "      'Authorization': 'Bearer ' + token,"
    "      'Content-Type': 'application/json'"
    "    },"
    "    body: jsonText"
    "  });"
    "  var statusDiv = document.getElementById('status');"
    "  if (resp.ok) {"
    "    statusDiv.textContent = 'Saved! You can close this tab.';"
    "  } else {"
    "    var msg = await resp.text();"
    "    statusDiv.textContent = 'Error: ' + msg;"
    "  }"
    "};"
    "</script>"
    "</body></html>"
)


def _build_relay_app(
    server_name: str,
    expected_token: str,
    on_save: Callable[[str, dict], None],
    shutdown_event: threading.Event,
) -> Starlette:
    """Build a Starlette app exposing ``GET /setup`` and ``POST /setup/submit``.

    The token is validated on both endpoints. Successful POST invokes
    ``on_save`` synchronously and signals ``shutdown_event`` so the watchdog
    thread can stop uvicorn.
    """

    async def setup_form(request: Request) -> HTMLResponse:
        token = request.query_params.get("token", "")
        if token != expected_token:
            return HTMLResponse("invalid token", status_code=401)
        body = _HTML_FORM_TEMPLATE.replace("SERVER_NAME", server_name)
        return HTMLResponse(body)

    async def submit(request: Request) -> JSONResponse:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer ") or auth[len("Bearer ") :] != expected_token:
            return JSONResponse({"error": "invalid token"}, status_code=401)
        try:
            creds = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid json body"}, status_code=400)
        if not isinstance(creds, dict):
            return JSONResponse({"error": "body must be a JSON object"}, status_code=400)
        try:
            on_save(server_name, creds)
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"error": f"on_save failed: {exc}"}, status_code=500)
        shutdown_event.set()
        return JSONResponse({"status": "saved"})

    return Starlette(
        routes=[
            Route("/setup", setup_form, methods=["GET"]),
            Route("/setup/submit", submit, methods=["POST"]),
        ]
    )


def register_relay_form_tool(
    mcp: Any,
    server_name: str,
    on_save: Callable[[str, dict], None],
    *,
    timeout_seconds: int = 600,
) -> None:
    """Register a ``config__open_relay`` tool on the given FastMCP server.

    When the tool is invoked, this helper:

    1. Picks a free localhost port and a random bearer token.
    2. Spawns a uvicorn server on a daemon thread serving the credential form.
    3. Starts a watchdog thread that flips ``server.should_exit`` when the
       user submits the form (success path) or after ``timeout_seconds``
       elapses (idle path).
    4. Tries to open the user's browser to the form URL.
    5. Returns the URL + status to the caller (the LLM tool result).

    Args:
        mcp: A FastMCP instance to register the tool on.
        server_name: Plugin server name (e.g. ``"wet-mcp"``). Passed to
            ``on_save`` so a single callback can multiplex over plugins.
        on_save: Callback invoked with ``(server_name, credentials_dict)``
            when the user submits the form. The caller is responsible for
            persisting the credentials (e.g. writing ``config.enc``).
        timeout_seconds: Auto-shutdown after this many seconds of idleness
            (default 600 = 10 minutes).
    """

    @mcp.tool(name="config__open_relay")
    async def open_relay() -> dict:
        """Open the credential setup form in your browser.

        Returns the URL and starts a transient HTTP server that self-
        shutdowns after submit or 10 minutes idle.
        """
        port = _find_free_port()
        token = _generate_token()
        url = f"http://127.0.0.1:{port}/setup?token={token}"

        shutdown_event = threading.Event()
        app = _build_relay_app(server_name, token, on_save, shutdown_event)

        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        server = uvicorn.Server(config)

        def _run_server() -> None:
            asyncio.run(server.serve())

        thread = threading.Thread(target=_run_server, daemon=True, name=f"relay-{server_name}")
        thread.start()

        def _watchdog() -> None:
            shutdown_event.wait(timeout_seconds)
            server.should_exit = True

        watchdog_thread = threading.Thread(target=_watchdog, daemon=True, name=f"relay-watchdog-{server_name}")
        watchdog_thread.start()

        # Wait briefly for the server to be listening so the URL we hand back
        # is immediately usable. Bound the wait at ~2s.
        for _ in range(20):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.1)

        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            # The browser may be unavailable (headless CI, locked-down user
            # session). The caller can still copy the URL manually from the
            # tool result.
            pass

        return {
            "url": url,
            "status": "browser_opened",
            "instructions": (
                f"Browser opened to {url}. Submit credentials to complete setup. "
                "Server self-shutdowns after submit or 10 minutes idle."
            ),
        }
