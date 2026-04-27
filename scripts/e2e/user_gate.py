"""Print user-gate URL to stderr, poll server for completion.

Used for T2 interaction configs. After the relay form is auto-filled, the
upstream provider (Notion / Microsoft / GDrive / Telegram) requires a human
click to grant consent or type an OTP. The driver does NOT automate the
browser per ``feedback_relay_fill_all_fields.md`` — automation = mock layer
that bypasses the real validation.

Instead the driver prints the gate URL and polls a status endpoint until the
server reports completion. Progress is echoed every 30s with the latest
``setup-status`` body so a stuck upstream consent surface is visible at
glance instead of looking like a hung driver.
"""

from __future__ import annotations

import json
import sys
import time

import httpx

_PROGRESS_LOG_INTERVAL = 30.0


def announce_and_wait(
    gate_description: str,
    relay_url: str,
    poll_url: str,
    timeout: float = 600.0,
) -> None:
    """Print gate banner to stderr, poll ``poll_url`` for ``state=complete``.

    Echoes ``[gate] elapsed=Xs remaining=Ys status=<body>`` every 30s while
    waiting so a stuck upstream consent doesn't look like a hung driver.

    Raises:
        RuntimeError: if the poll endpoint returns ``state=error``.
        TimeoutError: if ``timeout`` seconds elapse without completion.
    """
    bar = "=" * 60
    print(f"\n{bar}", file=sys.stderr)
    print(f"[USER ACTION REQUIRED] {gate_description}", file=sys.stderr)
    print(f"Relay URL: {relay_url}", file=sys.stderr)
    print(f"{bar}\n", file=sys.stderr)

    start = time.time()
    deadline = start + timeout
    last_log = 0.0
    while time.time() < deadline:
        try:
            r = httpx.get(poll_url, timeout=5.0)
            if r.status_code == 200:
                data = r.json()
                now = time.time()
                if (now - last_log) >= _PROGRESS_LOG_INTERVAL:
                    elapsed = int(now - start)
                    remaining = int(deadline - now)
                    print(
                        f"[gate] elapsed={elapsed}s remaining={remaining}s "
                        f"status={json.dumps(data)}",
                        file=sys.stderr,
                    )
                    last_log = now
                state = data.get("state") or next(iter(data.values()), None)
                if state == "complete":
                    return
                if state == "error":
                    raise RuntimeError(f"User gate failed: {data}")
        except (httpx.HTTPError, ValueError):
            pass
        time.sleep(3)
    raise TimeoutError(
        f"User gate not completed within {timeout}s ({gate_description})"
    )
