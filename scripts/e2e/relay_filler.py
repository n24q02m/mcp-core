"""Auto-fill mcp-core relay form via httpx — no browser automation.

Fetches ``GET /authorize`` HTML, parses ``<form>`` action + ``<input>`` names,
POSTs only the credentials whose names match form inputs (avoids leaking the
full skret bundle to a server that didn't ask for those keys).

Used for T2 non-interaction configs where the driver fills the relay form
without user interaction. T2 interaction configs run this AND additionally
poll a status endpoint while the user clicks the upstream consent / device-code
gate (see :mod:`e2e.user_gate`).
"""

from __future__ import annotations

import re

import httpx

_FORM_RE = re.compile(r'<form[^>]*action="([^"]+)"', re.IGNORECASE)
_INPUT_RE = re.compile(r'<input[^>]*name="([^"]+)"', re.IGNORECASE)


def fill_relay_form(
    base_url: str, creds: dict[str, str], timeout: float = 30.0
) -> dict:
    """Fill ``/authorize`` form once. Returns the JSON response body when the
    server returns JSON, otherwise ``{"status_code": int, "text": str}``.
    """
    # Follow redirects on GET: mcp-core's /authorize without OAuth params
    # 302-redirects to the bootstrapped /authorize?<PKCE-params> URL where
    # the form HTML is actually served. Without follow_redirects=True,
    # httpx raises HTTPStatusError on the 302.
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        r = client.get(f"{base_url}/authorize")
        r.raise_for_status()
        action_m = _FORM_RE.search(r.text)
        if not action_m:
            raise RuntimeError(f"No form action in {base_url}/authorize")

        action = action_m.group(1)
        action_url = action if action.startswith("http") else f"{base_url}{action}"

        input_names = set(_INPUT_RE.findall(r.text))
        payload = {k: v for k, v in creds.items() if k in input_names}

        # POST stays follow_redirects=True — server may 303 to /callback-done
        # after credential save (relay completion path).
        post = client.post(action_url, data=payload)
        post.raise_for_status()
        try:
            return post.json()
        except ValueError:
            return {"status_code": post.status_code, "text": post.text}
