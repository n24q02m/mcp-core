## 2024-04-21 - Batch Random Generation for Passphrases
**Learning:** Rejection sampling in loops utilizing FFI boundary calls (`crypto.getRandomValues()` in TS, `secrets.token_hex()` or `secrets.randbelow()` in Python) incurs massive per-invocation overhead.
**Action:** When performing rejection sampling, batch allocate randomness upfront (e.g., via `secrets.token_bytes()` or a correctly sized `Uint16Array`). In TypeScript, use a single, module-scoped fallback buffer when resampling to prevent garbage collection hits.
## 2025-04-22 - Optimize TextEncoder Instantiation
**Learning:** Instantiating `new TextEncoder()` inside hot functions like `encrypt()` and `deriveAesKey()` causes a measurable performance hit due to repetitive object allocation and native binding overhead. Reusing a module-scoped instance is significantly faster (~4.5x faster in tight loops).
**Action:** When a utility class like `TextEncoder` or `TextDecoder` doesn't hold request-specific state, instantiate it once at the module level and reuse it across function calls.
