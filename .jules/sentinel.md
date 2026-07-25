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
## 2024-06-21 - [SECURITY] Potential Command Injection via `execFile`
**Vulnerability:** Too permissive URL validation regex allowed shell metacharacters (`$`, `(`, `)`) which could be interpreted by `wslview` in WSL environments.
**Learning:** Even when using `execFile` (which avoids shell invocation), downstream utilities like `wslview` might pass arguments to a shell. Base64 encoding parameters (e.g., via PowerShell's `-EncodedCommand`) provides a much safer way to pass complex strings across the Linux/Windows boundary in WSL.
**Prevention:** Tighten input validation regexes to exclude shell metacharacters. Prioritize safer execution methods that use encoding (like Base64) over direct parameter passing to utilities that might invoke a shell.

## 2026-07-02 - [Clickjacking via HTML responses without X-Frame-Options in router.ts]
**Vulnerability:** Missing X-Frame-Options header in the `htmlResponse` helper of the router allows clickjacking attacks by enabling the page to be embedded in an iframe.
**Learning:** When serving custom HTML responses (e.g., error pages, setup forms) directly from server endpoints, they must explicitly include the `X-Frame-Options: DENY` HTTP header to prevent clickjacking.
**Prevention:** Ensure all utility functions that generate HTML responses (like `htmlResponse`) automatically inject the `X-Frame-Options: DENY` header.
## 2026-07-10 - [Insecure Directory Permissions Fix]
**Vulnerability:** Directories for sensitive components (caches, configs, session locks, SQLite user stores) in both `core-py` and `core-ts` were created without explicit restrictive permissions in the initial `mkdir`/`mkdirSync` call, creating a Time-Of-Check to Time-Of-Use (TOCTOU) race condition window where the directories could be created with the system's default, more permissive umask.
**Learning:** Depending on a subsequent `chmod` call to tighten directory permissions leaves a brief window where an attacker could access or modify the directory.
**Prevention:** Always explicitly set the mode during directory creation (e.g., `mode=0o700` in Python's `mkdir`, `mode: 0o700` in Node.js's `mkdirSync`) when handling sensitive configuration or cache data.

## 2026-07-25 - [TOCTOU in File Permissions Setting]
**Vulnerability:** Files written with default permissions (like `writeFileSync` or `write_text`) and subsequently restricted using `chmod` are vulnerable to Time-Of-Check to Time-Of-Use (TOCTOU) race conditions.
**Learning:** During the window between file creation and the `chmod` operation, an attacker could potentially access or modify the file content, because it briefly exists with broader system default permissions (e.g., `0o644`).
**Prevention:** Instead of modifying permissions retroactively, permissions should be explicitly defined during file creation. For Node.js, `writeFileSync` should use `mode: 0o600`. For Python, use `os.open(..., mode=0o600)` with `os.fdopen`.

## 2024-05-18 - Prevent TOCTOU via Explicit File Creation Permissions
**Vulnerability:** File creation using standard mechanisms like `open(..., "w")` followed by `os.chmod()` leaves a Time-Of-Check to Time-Of-Use (TOCTOU) vulnerability window where the file exists with the system default umask permissions before being restricted.
**Learning:** This is particularly dangerous for sensitive files like cryptographic keys (e.g. RSA keys), configuration stores (`config.enc`), and session locks which require strict owner-only access (`0o600` or `0o644`). The window allows a concurrent attacker to read or modify the file during this brief interval.
**Prevention:** Always create sensitive files using `os.open` with `os.O_CREAT` and specify the strict `mode` directly (e.g. `os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)`). Then, wrap the file descriptor in `os.fdopen()` to interact with it as a standard file object. Do not rely on a subsequent `os.chmod()` after creation.
