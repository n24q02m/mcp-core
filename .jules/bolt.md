## 2025-04-12 - Cached PBKDF2 Key Derivation
**Learning:** The config file encryption used PBKDF2 with 600,000 iterations inside `deriveFileKey()`, which was being called on *every* config file read and write. This caused severe performance bottlenecks, taking over 3 seconds to execute a simple loop of 10 reads. Caching the derived key in memory significantly reduces this CPU overhead (down to ~5ms for the same loop).
**Action:** When working with cryptography in this codebase, specifically PBKDF2 key derivations in `packages/core-ts`, ensure the result is cached for subsequent operations within the same process lifecycle to avoid unnecessary CPU blocking. Remember to provide a way to clear the cache for isolated unit testing (e.g., `clearKeyCacheForTesting`).

## 2025-05-14 - Invariant String Transformation Hoisting
**Learning:** Invariant string transformations (e.g., `re.sub(r"-", "_", server_name).upper()`) within loops can lead to redundant computation. Hoisting these operations outside the loop improves efficiency, especially for large collections.
**Action:** Always scan loops for operations that do not depend on the loop iterator and move them outside the loop body.
