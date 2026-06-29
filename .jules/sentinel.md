## 2026-06-18 - [Timing Attack in hmac.compare_digest]
**Vulnerability:** `hmac.compare_digest` returning early leaks the length of the secret when lengths differ, which reduces the secret entropy.
**Learning:** In Python, `hmac.compare_digest` and `secrets.compare_digest` return false instantly on unequal lengths. This makes the secret length vulnerable to a timing attack.
**Prevention:** Use a wrapper function `_timing_safe_equal` that pads the comparison to the same length of the user input, so execution time only depends on the attacker-controlled input length.

## 2024-05-30 - Add X-Frame-Options to HTML Responses
**Vulnerability:** Missing X-Frame-Options header on HTML pages returned from server endpoints.
**Learning:** Returning HTML pages directly from server endpoints (e.g., using Starlette's `HTMLResponse` or Express's `res.send`) without `X-Frame-Options: DENY` allows clickjacking attacks.
**Prevention:** When returning HTML pages directly from server endpoints, always include the HTTP header `{"X-Frame-Options": "DENY"}` to prevent clickjacking attacks.

## 2025-06-29 - Insecure Directory Permissions for Lockfiles
**Vulnerability:** The lock directory for lifecycle lockfiles was created using `mkdir(parents=True, exist_ok=True)` without an explicit `mode`. This allowed the directory to be created with overly broad permissions based on the system umask (often 0o775 or 0o777 in certain environments), creating a race condition window where an attacker could potentially access the directory before the subsequent `chmod(0o700)` call.
**Learning:** Always use the `mode` parameter in `mkdir` when creating directories that will contain sensitive information (like tokens or lockfiles) to ensure they are created securely from the start.
**Prevention:** Audit all `mkdir` calls in the codebase and ensure security-sensitive directories use `mode=0o700`.
