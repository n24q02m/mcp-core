## 2024-04-21 - Batch Random Generation for Passphrases
**Learning:** Rejection sampling in loops utilizing FFI boundary calls (`crypto.getRandomValues()` in TS, `secrets.token_hex()` or `secrets.randbelow()` in Python) incurs massive per-invocation overhead.
**Action:** When performing rejection sampling, batch allocate randomness upfront (e.g., via `secrets.token_bytes()` or a correctly sized `Uint16Array`). In TypeScript, use a single, module-scoped fallback buffer when resampling to prevent garbage collection hits.
