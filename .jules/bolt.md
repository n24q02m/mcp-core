## 2024-04-21 - Batch Random Generation for Passphrases
**Learning:** Rejection sampling in loops utilizing FFI boundary calls (`crypto.getRandomValues()` in TS, `secrets.token_hex()` or `secrets.randbelow()` in Python) incurs massive per-invocation overhead.
**Action:** When performing rejection sampling, batch allocate randomness upfront (e.g., via `secrets.token_bytes()` or a correctly sized `Uint16Array`). In TypeScript, use a single, module-scoped fallback buffer when resampling to prevent garbage collection hits.
## 2025-04-22 - Optimize TextEncoder Instantiation
**Learning:** Instantiating `new TextEncoder()` inside hot functions like `encrypt()` and `deriveAesKey()` causes a measurable performance hit due to repetitive object allocation and native binding overhead. Reusing a module-scoped instance is significantly faster (~4.5x faster in tight loops).
**Action:** When a utility class like `TextEncoder` or `TextDecoder` doesn't hold request-specific state, instantiate it once at the module level and reuse it across function calls.
## 2025-04-26 - Optimize Polling Append-Only Arrays
**Learning:** Native `Array.prototype.find` (or `.findLast`) incurs heavy O(N) overhead in hot polling loops when searching large, append-only response arrays repeatedly. The Bun runtime makes this overhead especially pronounced compared to raw indexed loops.
**Action:** When polling an array that only ever grows (append-only), keep track of `lastSeenCount`. On subsequent polls, execute a manual `for` loop starting from the end of the array down to `lastSeenCount`. This prevents redundant O(N) scanning of older elements, making the total amortized cost O(N_total) rather than O(Polls * N).
## 2025-05-04 - [Avoid fragile optimizations and micro-optimizing small loop iterations]
**Learning:** In Python, attempting to optimize a short loop (like scanning a small JSON list `responses` in `poll_for_responses`) by keeping a `last_seen_count` state to skip previously scanned elements provides zero measurable performance gain, because the time saved (fractions of a millisecond) is dwarfed by the massive HTTP request latency and `asyncio.sleep()` in the same loop. Furthermore, assuming the server array is append-only is dangerous and could break if the server starts paginating or clearing old items.
**Action:** Do not micro-optimize small iterations in Python when the loop contains expensive operations (like I/O or network requests), and never assume an external API's response array is strictly append-only without verification.

## 2024-05-24 - Cookie Parsing Hot Path Avoids Array Allocations
**Learning:** In hot paths like HTTP cookie parsing (`parseCookies` in `local-oauth-app.ts` and `delegated-oauth-app.ts`), splitting strings via `split(';')` generates unnecessary array allocations and intermediate strings. A single-pass `while` loop using `indexOf` and `substring()` is demonstrably faster (~10% improvement in basic tests) and reduces GC pressure while avoiding additional dependencies.
**Action:** Always prefer index-based scanning and substring extraction for parsing small text structures (like headers or cookies) in high-frequency functions. Ensure functional parity with extensive edge case tests for trailing symbols and missing separators.
## $(date +%Y-%m-%d) - [Optimize Dictionary Pruning]
**Learning:** In Python, resetting a dictionary by creating a new one (e.g., using dict comprehension) and then using `clear` and `update` is O(N). For pruning scenarios where only a small number of items are deleted (e.g., expired sessions), it's faster to find the expired keys and delete them using `del dict[key]`, making it O(K).
**Action:** Use targeted deletion (`del dict[key]`) over full dictionary rebuilds for pruning operations to achieve O(K) complexity instead of O(N-K).

## 2026-07-09 - [Optimize String Concatenation in Python]
**Learning:** In Python, when repeating strings like SQL placeholders in a loop, list multiplication (e.g. `[val] * count`) is executed entirely in C and is significantly faster than using a generator expression inside `.join()`.
**Action:** Use list multiplication for repeating static strings or tuples instead of generator loops when performance is critical.
