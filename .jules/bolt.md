## 2025-04-12 - Cached PBKDF2 Key Derivation
**Learning:** The config file encryption used PBKDF2 with 600,000 iterations inside `deriveFileKey()`, which was being called on *every* config file read and write. This caused severe performance bottlenecks, taking over 3 seconds to execute a simple loop of 10 reads. Caching the derived key in memory significantly reduces this CPU overhead (down to ~5ms for the same loop).
**Action:** When working with cryptography in this codebase, specifically PBKDF2 key derivations in `packages/core-ts`, ensure the result is cached for subsequent operations within the same process lifecycle to avoid unnecessary CPU blocking. Remember to provide a way to clear the cache for isolated unit testing (e.g., `clearKeyCacheForTesting`).

## 2026-04-16 - [PERF] Uint16Array reuse in random generation loop
**Learning:** Instantiating a new `Uint16Array` within a loop for `crypto.getRandomValues()` creates unnecessary memory allocation and garbage collection pressure. Reusing a single pre-allocated buffer outside the loop reduces overhead, especially in performance-sensitive paths like passphrase generation.
**Action:** Always hoist typed array allocations (e.g., `Uint16Array`, `Uint8Array`) used for random byte retrieval outside of loops and reuse the same buffer.
