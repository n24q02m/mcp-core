## 2026-06-18 - [Timing Attack in hmac.compare_digest]
**Vulnerability:** `hmac.compare_digest` returning early leaks the length of the secret when lengths differ, which reduces the secret entropy.
**Learning:** In Python, `hmac.compare_digest` and `secrets.compare_digest` return false instantly on unequal lengths. This makes the secret length vulnerable to a timing attack.
**Prevention:** Use a wrapper function `_timing_safe_equal` that pads the comparison to the same length of the user input, so execution time only depends on the attacker-controlled input length.

## 2024-05-30 - Add X-Frame-Options to HTML Responses
**Vulnerability:** Missing X-Frame-Options header on HTML pages returned from server endpoints.
**Learning:** Returning HTML pages directly from server endpoints (e.g., using Starlette's `HTMLResponse` or Express's `res.send`) without `X-Frame-Options: DENY` allows clickjacking attacks.
**Prevention:** When returning HTML pages directly from server endpoints, always include the HTTP header `{"X-Frame-Options": "DENY"}` to prevent clickjacking attacks.
## 2026-06-25 - SQL Injection Risk in D1 `executemany`
**Vulnerability:** Manual SQL string manipulation (concatenation) during multi-row INSERT optimization in D1 backend.
**Learning:** Manual template expansion, even if parameters are bound, is a high-risk pattern and often flagged by SAST. Supporting native batch endpoints (like Cloudflare D1's `/batch`) provides a safer and more robust alternative for non-standard or complex SQL.
**Prevention:** Avoid any runtime SQL string concatenation. Use strict regex whitelisting if template repetition is necessary for performance, and always provide a safe fallback using native batch APIs.
