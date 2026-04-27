## 2024-04-21 - Batch Random Generation for Passphrases
**Learning:** Rejection sampling in loops utilizing FFI boundary calls (`crypto.getRandomValues()` in TS, `secrets.token_hex()` or `secrets.randbelow()` in Python) incurs massive per-invocation overhead.
**Action:** When performing rejection sampling, batch allocate randomness upfront (e.g., via `secrets.token_bytes()` or a correctly sized `Uint16Array`). In TypeScript, use a single, module-scoped fallback buffer when resampling to prevent garbage collection hits.
## 2025-04-22 - Optimize TextEncoder Instantiation
**Learning:** Instantiating `new TextEncoder()` inside hot functions like `encrypt()` and `deriveAesKey()` causes a measurable performance hit due to repetitive object allocation and native binding overhead. Reusing a module-scoped instance is significantly faster (~4.5x faster in tight loops).
**Action:** When a utility class like `TextEncoder` or `TextDecoder` doesn't hold request-specific state, instantiate it once at the module level and reuse it across function calls.
## 2025-04-26 - Optimize Polling Append-Only Arrays
**Learning:** Native `Array.prototype.find` (or `.findLast`) incurs heavy O(N) overhead in hot polling loops when searching large, append-only response arrays repeatedly. The Bun runtime makes this overhead especially pronounced compared to raw indexed loops.
**Action:** When polling an array that only ever grows (append-only), keep track of `lastSeenCount`. On subsequent polls, execute a manual `for` loop starting from the end of the array down to `lastSeenCount`. This prevents redundant O(N) scanning of older elements, making the total amortized cost O(N_total) rather than O(Polls * N).
