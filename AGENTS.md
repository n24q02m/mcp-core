# AGENTS.md - mcp-core

## For Implementation Agents

This is a monorepo with 3 Python packages + 1 TypeScript package. When working on a task:

- TypeScript package (`core-ts`): use bun for package management, vitest for tests, biome for lint/format
- Python packages (`core-py`, `embedding-daemon`, `stdio-proxy`): use uv for package management, pytest for tests, ruff for lint/format, ty for type checking
- Pre-commit hooks enforce: biome (TS), ruff (Python), gitleaks (secrets), conventional commits (feat/fix only)
- Coverage target: >= 95%
- Commit prefix: `feat:` or `fix:` only (PSR release commit `chore(release):` is a whitelisted exception)

## Package Boundaries

- `core-py` and `core-ts` MUST produce identical crypto output for the same inputs (ECDH P-256 + AES-256-GCM + HKDF-SHA256)
- `embedding-daemon` is independent — shares types only via HTTP API contract (FastAPI + Pydantic)
- `stdio-proxy` is independent — no shared code with other packages
- Test vectors in `packages/core-ts/tests/fixtures/crypto-vectors.json` are the parity contract between core-ts and core-py

## Tooling

- **Runtimes**: mise (tools), Node 24, Python 3.13, bun latest, uv latest
- **Package managers**: bun (TS workspace at repo root), uv (per-package for Python)
- **Linters**: biome (TS), ruff (Python), gitleaks (secrets)
- **Type checkers**: tsc (TS), ty (Python)
- **Tests**: vitest (TS), pytest (Python)
- **Release**: python-semantic-release v10 (PSR) bumps all 3 Python pyproject.toml files via `version_toml` (core-py, embedding-daemon, stdio-proxy). CD injects version into `packages/core-ts/package.json` before npm publish.
