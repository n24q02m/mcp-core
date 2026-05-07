"""Transient relay HTTP server for stdio-mode plugins.

When a plugin runs in stdio mode (no long-running daemon), the
``config__open_relay`` tool spawns an in-process HTTP server only when called.
The server self-shutdowns after credentials are submitted, after a 10-minute
idle timeout, or when the plugin process exits.

This is the stdio-mode counterpart to the HTTP-mode persistent ``/setup``
endpoint served by ``mcp_core.transport.local_server.run_http_server``. It
intentionally uses Starlette (already a transitive dependency via FastMCP)
rather than FastAPI to avoid pulling a new top-level dependency for a
single-form server.
"""

from __future__ import annotations

import asyncio
import html
import json
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


# Form HTML uses ``textContent`` only -- no ``innerHTML`` with untrusted
# content. Two distinct placeholders for two contexts:
#   * ``__SERVER_NAME_HTML__`` rendered into HTML markup (escaped via
#     ``html.escape``).
#   * ``__SERVER_NAME_JS__`` rendered into a JS string literal slot
#     (encoded via ``json.dumps`` which produces a valid JS string).
# A plugin author who picks a malicious server name (e.g.
# ``"</script><script>alert(1)</script>"``) cannot escape either context.
_HTML_FORM_TEMPLATE = (
    "<!DOCTYPE html><html><head><title>__SERVER_NAME_HTML__ setup</title></head>"
    "<body><h1 id='title'></h1>"
    "<p>Paste a JSON object containing your credentials below, then click "
    "Submit. The form auto-closes after a successful save.</p>"
    "<form id='relayForm'>"
    "__FORM_FIELDS__"
    "<button type='submit'>Submit</button>"
    "</form>"
    "<div id='status'></div>"
    "<script>"
    "document.getElementById('title').textContent = __SERVER_NAME_JS__ + ' credentials';"
    "document.getElementById('relayForm').onsubmit = async function(e) {"
    "  e.preventDefault();"
    "  var token = new URLSearchParams(window.location.search).get('token');"
    "  var form = e.target;"
    "  var body;"
    "  if (form.dataset.mode === 'json') {"
    "    body = form.elements['json'].value;"
    "  } else {"
    "    var obj = {};"
    "    var inputs = form.querySelectorAll('input[name], textarea[name], select[name]');"
    "    for (var i = 0; i < inputs.length; i++) {"
    "      var el = inputs[i];"
    "      if (el.name === 'json') continue;"
    "      obj[el.name] = el.value;"
    "    }"
    "    body = JSON.stringify(obj);"
    "  }"
    "  var resp = await fetch('/setup/submit', {"
    "    method: 'POST',"
    "    headers: {"
    "      'Authorization': 'Bearer ' + token,"
    "      'Content-Type': 'application/json'"
    "    },"
    "    body: body"
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


def _render_form_fields(relay_schema: dict[str, Any] | None) -> tuple[str, str]:
    """Render form-field markup for the form body.

    Returns a tuple ``(fields_html, mode)`` where ``mode`` is ``"json"`` for
    the generic textarea fallback and ``"fields"`` for the schema-driven
    labeled-inputs path. The mode is set as a ``data-mode`` attribute on the
    ``<form>`` element so the inline submit script knows whether to read a
    raw JSON textarea or to collect named inputs into an object.
    """
    if relay_schema is None or not relay_schema.get("fields"):
        # Fallback: generic JSON paste textarea. Uses ``name="json"`` so the
        # inline script's ``form.dataset.mode === 'json'`` branch reads it.
        textarea = (
            "<textarea name='json' rows='10' cols='60' "
            "placeholder='{&quot;api_key&quot;: &quot;...&quot;}'></textarea><br>"
        )
        return textarea, "json"

    parts: list[str] = []
    for field in relay_schema["fields"]:
        # Each field dict: ``{"name": str, "label": str, "type": str?,
        # "placeholder": str?, "required": bool?}``. Every value rendered into
        # HTML markup is run through ``html.escape`` to defuse a malicious
        # plugin author choosing weird strings.
        raw_name = str(field.get("name", ""))
        if not raw_name:
            continue
        name_attr = html.escape(raw_name, quote=True)
        label_text = html.escape(str(field.get("label", raw_name)))
        input_type = html.escape(str(field.get("type", "text")), quote=True)
        placeholder = html.escape(str(field.get("placeholder", "")), quote=True)
        required_attr = " required" if field.get("required") else ""
        parts.append(
            f"<label>{label_text}<br>"
            f"<input type='{input_type}' name='{name_attr}' "
            f"placeholder='{placeholder}'{required_attr}></label><br>"
        )
    return "".join(parts), "fields"


def _build_relay_app(
    server_name: str,
    expected_token: str,
    on_save: Callable[[str, dict], None],
    shutdown_event: threading.Event,
    relay_schema: dict[str, Any] | None = None,
) -> Starlette:
    """Build a Starlette app exposing ``GET /setup`` and ``POST /setup/submit``.

    The token is validated on both endpoints with ``secrets.compare_digest`` to
    avoid timing-based extraction. Successful POST invokes ``on_save``
    synchronously, then schedules a brief delayed shutdown signal so the HTTP
    response can flush before uvicorn closes the connection.
    """
    fields_html, form_mode = _render_form_fields(relay_schema)
    # ``json.dumps`` produces a valid JS string literal but does NOT escape
    # ``</script>``, which the HTML parser closes regardless of JS syntax.
    # Replace ``</`` with ``<\/`` (still a valid JS string, but the HTML
    # tokenizer no longer sees a script-closing tag).
    server_name_js = json.dumps(server_name).replace("</", "<\\/")
    body_template = (
        _HTML_FORM_TEMPLATE.replace("__SERVER_NAME_HTML__", html.escape(server_name))
        .replace("__SERVER_NAME_JS__", server_name_js)
        .replace("__FORM_FIELDS__", fields_html)
    )
    # Inject the form-mode marker as a ``data-mode`` attribute on the
    # ``<form>`` element so the inline JS knows whether to read the
    # ``json`` textarea or assemble an object from named inputs.
    body_template = body_template.replace(
        "<form id='relayForm'>",
        f"<form id='relayForm' data-mode='{html.escape(form_mode, quote=True)}'>",
    )

    async def setup_form(request: Request) -> HTMLResponse:
        token = request.query_params.get("token", "")
        if not secrets.compare_digest(token, expected_token):
            return HTMLResponse("invalid token", status_code=401)
        return HTMLResponse(body_template)

    async def submit(request: Request) -> JSONResponse:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"error": "invalid token"}, status_code=401)
        provided = auth[len("Bearer ") :]
        if not secrets.compare_digest(provided, expected_token):
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

        # Delay the shutdown signal so uvicorn can flush this response before
        # the watchdog flips ``server.should_exit`` and closes the socket.
        # 0.5s is generous for a localhost JSON response.
        def _delayed_shutdown() -> None:
            time.sleep(0.5)
            shutdown_event.set()

        threading.Thread(
            target=_delayed_shutdown,
            daemon=True,
            name=f"relay-shutdown-{server_name}",
        ).start()

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
    relay_schema: dict[str, Any] | None = None,
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
            HTML- and JS-escaped before being interpolated into the form.
        on_save: Callback invoked with ``(server_name, credentials_dict)``
            when the user submits the form. The caller is responsible for
            persisting the credentials (e.g. writing ``config.enc``).
        relay_schema: Optional schema describing the credential fields.
            Shape: ``{"fields": [{"name": str, "label": str, "type": str?,
            "placeholder": str?, "required": bool?}, ...]}``. When provided
            the form renders labeled inputs (UX parity with HTTP-daemon mode
            per ``feedback_relay_mode_ui_parity.md``); when ``None`` the
            form falls back to a generic JSON-paste textarea.
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
        app = _build_relay_app(server_name, token, on_save, shutdown_event, relay_schema)

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
        # is immediately usable. Bound the wait at ~2s, yielding to the event
        # loop between probes so we don't block the host MCP server.
        for _ in range(20):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                await asyncio.sleep(0.1)

        try:
            # ``webbrowser.open`` may block briefly on Windows while it spawns
            # the OS handler; run it in a worker thread to keep the asyncio
            # loop responsive.
            await asyncio.to_thread(webbrowser.open, url)
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
