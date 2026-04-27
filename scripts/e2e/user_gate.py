"""Print user-gate URL to stderr, poll server for completion.

Used for T2 interaction configs. After the relay form is auto-filled, the
upstream provider (Notion / Microsoft / GDrive / Telegram) requires a human
click to grant consent or type an OTP. The driver does NOT automate the
browser per ``feedback_relay_fill_all_fields.md`` — automation = mock layer
that bypasses the real validation.

Instead the driver prints the gate URL and polls a status endpoint until the
server reports completion.
"""

from __future__ import annotations

import sys
import time

import httpx


def announce_and_wait(
    gate_description: str,
    relay_url: str,
    poll_url: str,
    timeout: float = 600.0,
) -> None:
    """Print gate banner to stderr, poll ``poll_url`` for ``state=complete``.

    Raises:
        RuntimeError: if the poll endpoint returns ``state=error``.
        TimeoutError: if ``timeout`` seconds elapse without completion.
    """
    bar = "=" * 60
    print(f"\n{bar}", file=sys.stderr)
    print(f"[USER ACTION REQUIRED] {gate_description}", file=sys.stderr)
    print(f"Relay URL: {relay_url}", file=sys.stderr)
    print(f"{bar}\n", file=sys.stderr)

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(poll_url, timeout=5.0)
            if r.status_code == 200:
                data = r.json()
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
