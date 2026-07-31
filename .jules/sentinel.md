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

## 2026-08-01 - [TOCTOU in core-py file creation, and the O_APPEND trap in the fix]
**Vulnerability:** Four core-py paths created a sensitive file with `open()` / `write_bytes()` / `write_text()` and narrowed it with `chmod` afterwards: the lifecycle lock (contains the proxy token), the JWT private key, the encrypted credential blob, and the session lock. Each left the file under the process umask for the duration of the write.
**Learning:** Porting `open(path, "a+")` to `os.open` is not a mechanical substitution. `"a+"` sets `O_APPEND`, under which *every* write goes to end-of-file and an intervening `seek(0)` is silently ignored. The lock file relied on `seek(0)` + a 512-byte padded record to overwrite in place, so it had in fact been appending a second record whenever it re-acquired a lock file that survived an unclean exit — and since `_parse_lock_text` reads the leading four lines, a dead PID was reported as the current lock holder. Carrying `O_APPEND` across preserves the bug; dropping it without noticing changes behaviour by accident. Either way the flag has to be a deliberate decision.
**Prevention:** Create sensitive files with `os.open(path, flags, mode)` and wrap in `os.fdopen`; close the descriptor explicitly if `fdopen` itself raises, since it only takes ownership on success. When replacing a mode string, enumerate the flags it implied and decide on each. Do not route a file whose permissions are intentionally broad (a public key) through `os.open` — its mode is subject to the umask, whereas `chmod` is not.

## Rejected

Bot proposals declined, with the technical reason. Recorded so the same change
does not come back as a fresh PR.

- **#701, #710 — "Fix TOCTOU vulnerabilities in file creation" (two variants of one change).** Both identified the right four call sites. #710 kept `O_APPEND` on the lifecycle lock and so preserved the stale-record bug described above; #701 dropped it, which was the correct end state but arrived as an unremarked, untested behaviour change — the PR body claimed only a permissions fix. Neither carried a test for the permission bits or for the overwrite semantics. Superseded by a hand-written change covering both properties with tests, including one that fails on the old code by reading a dead PID as the lock holder.
- **#702 — "Fix TOCTOU vulnerability in session lock creation".** A strict subset of #701/#710 (only `storage/session_lock.py`), same substance, same missing tests. Covered by the superseding change.
- **#705 — "Fix TOCTOU vulnerability in file permissions" (core-ts).** No-op. It adds `mode: 0o600` to the `writeFileSync` inside `refreshLockTimestamp`, but that function returns early unless the file already exists, and `mode` applies only when a file is created. The path that does create the lock file, `writeLockFile`, already passes `mode: 0o600`. Merging it would have recorded a fix that changes nothing.
