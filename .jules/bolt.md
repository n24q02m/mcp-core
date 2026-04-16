## 2025-04-12 - Cached PBKDF2 Key Derivation
**Learning:** The config file encryption used PBKDF2 with 600,000 iterations inside `deriveFileKey()`, which was being called on *every* config file read and write. This caused severe performance bottlenecks, taking over 3 seconds to execute a simple loop of 10 reads. Caching the derived key in memory significantly reduces this CPU overhead (down to ~5ms for the same loop).
**Action:** When working with cryptography in this codebase, specifically PBKDF2 key derivations in `packages/core-ts`, ensure the result is cached for subsequent operations within the same process lifecycle to avoid unnecessary CPU blocking. Remember to provide a way to clear the cache for isolated unit testing (e.g., `clearKeyCacheForTesting`).

## 2026-04-16 - Hoisted Invariant String Transformations in Loops
**Learning:** Performing invariant string operations (like `toUpperCase()` and `replace()`) inside loops adds unnecessary overhead, especially when the input is constant across iterations. Hoisting these transformations outside the loop reduces redundant computation.
**Action:** In `resolveConfig`, I hoisted `serverName.toUpperCase().replace(/-/g, '_')` out of the loop over required fields. Always scan loops for operations that don't depend on the loop variable and lift them out for better performance.
