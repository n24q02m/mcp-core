## 2024-04-14 - Python Config Key Caching
**Learning:** Python package (`core-py`) was missing the PBKDF2 derived file key caching that was present in the TypeScript equivalent. This meant expensive operations (600,000 PBKDF2 iterations taking ~350ms) were occurring on every config read/write call in the same process.
**Action:** Always verify feature parity between TypeScript and Python equivalents, especially for expensive operations like encryption where a single `bytes | None` cache makes an enormous difference. Remember to clear caches in pytest test setups to avoid state leakage.
