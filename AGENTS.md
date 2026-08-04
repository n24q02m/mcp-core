# AGENTS.md - mcp-core

## For Implementation Agents

This is a monorepo with 2 Python packages + 1 TypeScript package. When working on a task:

- TypeScript package (`core-ts`): use bun for package management, vitest for tests, biome for lint/format
- Python packages (`core-py`, `embedding-daemon`): use uv for package management, pytest for tests, ruff for lint/format, ty for type checking
- Pre-commit hooks enforce: biome (TS), ruff (Python), gitleaks (secrets), conventional commits (feat/fix only)
- Coverage target: >= 95%
- Commit prefix: `feat:` or `fix:` only (PSR release commit `chore(release):` is a whitelisted exception)
- PR title: same subset as the commit prefix — `feat:` or `fix:` (scope optional), lowercase subject, no agent name or emoji in front. `.github/workflows/pr-title.yml` reports it red otherwise, and the squash subject it produces is what PSR reads

## Package Boundaries

- `core-py` and `core-ts` MUST produce identical crypto output for the same inputs (ECDH P-256 + AES-256-GCM + HKDF-SHA256)
- `embedding-daemon` is independent — shares types only via HTTP API contract (FastAPI + Pydantic)
- Test vectors in `packages/core-ts/tests/fixtures/crypto-vectors.json` are the parity contract between core-ts and core-py

## Tooling

- **Runtimes**: mise (tools), Node 24, Python 3.13, bun latest, uv latest
- **Package managers**: bun (TS workspace at repo root), uv (per-package for Python)
- **Linters**: biome (TS), ruff (Python), gitleaks (secrets)
- **Type checkers**: tsc (TS), ty (Python)
- **Tests**: vitest (TS), pytest (Python)
- **Release**: python-semantic-release v10 (PSR) bumps both Python pyproject.toml files via `version_toml` (core-py, embedding-daemon). CD injects version into `packages/core-ts/package.json` before npm publish.

## Release Readiness and Cascade

- Before dispatching CD, release from `main` with a clean working tree, required CI and E2E checks green, no actionable open PRs, and no open Dependabot, code-scanning, or secret-scanning alerts. The standing Dependency Dashboard issue is the only issue allowlist. Resolve backlog or failing checks before dispatch; do not bypass them.
- A stable release also requires the beta cascade and Test B client matrix to pass against the published beta with real tool calls; T0 CI/E2E is not a substitute for Test B.
- The release job dry-runs PSR and checks the computed version against npm and both PyPI package coordinates before creating a tag or GitHub Release. Publishing jobs run only when PSR reports `released=true`.
- `beta` runs PSR as a prerelease with the `beta` token and publishes npm with the `beta` dist-tag. It does not create downstream bump issues.
- `stable` runs PSR as a stable release and publishes npm with the `latest` dist-tag. Only after the release, npm publish, and both PyPI publishes succeed does CD create downstream issues.
- Stable-only downstream fan-out is defined in `.github/workflows/cd.yml`:
  - Direct npm pin issues for `better-notion-mcp`, `better-email-mcp`, `better-godot-mcp`, and `better-workspace-mcp` for `@n24q02m/mcp-core`.
  - Direct PyPI pin issues for `better-telegram-mcp`, `wet-mcp`, `mnemo-mcp`, `better-code-review-graph`, and `imagine-mcp` for `n24q02m-mcp-core`.
  - Tracking issues for `qwen3-embed`, `web-core`, and `claude-plugins` to check their mcp-core integration or marketplace references.
- The downstream job searches existing issues before creating one. A direct pin issue asks for the dependency and lockfile update; a tracking issue may be closed with its verification result when no change is required.
