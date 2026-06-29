## 2026-06-18 - [Timing Attack in hmac.compare_digest]
**Vulnerability:** `hmac.compare_digest` returning early leaks the length of the secret when lengths differ, which reduces the secret entropy.
**Learning:** In Python, `hmac.compare_digest` and `secrets.compare_digest` return false instantly on unequal lengths. This makes the secret length vulnerable to a timing attack.
**Prevention:** Use a wrapper function `_timing_safe_equal` that pads the comparison to the same length of the user input, so execution time only depends on the attacker-controlled input length.

## 2024-05-30 - Add X-Frame-Options to HTML Responses
**Vulnerability:** Missing X-Frame-Options header on HTML pages returned from server endpoints.
**Learning:** Returning HTML pages directly from server endpoints (e.g., using Starlette's `HTMLResponse` or Express's `res.send`) without `X-Frame-Options: DENY` allows clickjacking attacks.
**Prevention:** When returning HTML pages directly from server endpoints, always include the HTTP header `{"X-Frame-Options": "DENY"}` to prevent clickjacking attacks.

## 2025-05-20 - [SECURITY] Potential Command Injection via xdg-open
**Vulnerability:** Shell characters like $, (, ), *, ,, and ; in a URL could lead to command injection if the underlying browser-opening tool (e.g., `xdg-open`) handles them unsafely or passes them to a shell.
**Learning:** Even though `execFile` (Node.js) and `subprocess.run` (Python) are generally safe from shell injection when not using `shell=True`, third-party utilities like `xdg-open` may have their own internal shell execution logic.
**Prevention:** Use a highly restrictive whitelist regex for URLs that are passed to external browser-opening tools. The tightened regex `^https?://[a-zA-Z0-9-._~:/?#\[\]@!$&'%+=]+$` excludes dangerous shell metacharacters while preserving valid OAuth URL characters.
