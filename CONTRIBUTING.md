# Contributing to mcp-core

Thanks for your interest in contributing! This document outlines the development workflow.

## Setup

Install [mise](https://mise.jdx.dev/) first, then run:

```bash
mise run setup
```

This installs all tool versions (Node 24, Python 3.13, bun, uv), Python/TS dependencies, and pre-commit hooks.

## Monorepo Layout

- `packages/core-py` — Python library (PyPI: `n24q02m-mcp-core`)
- `packages/core-ts` — TypeScript library (npm: `@n24q02m/mcp-core`)
- `packages/embedding-daemon` — Shared ONNX/GGUF embedding server
- `packages/stdio-proxy` — Thin stdio-to-HTTP forwarder

## Commit Messages

Only `feat:` and `fix:` prefixes are allowed (enforced by a pre-commit `commit-msg` hook). Breaking changes are NOT indicated via `!` — bump the major version via PSR conventions.

```
feat: add OAuth device code flow to core-py
fix: handle UTF-8 BOM in config file parser
```

The PSR release commit pattern `chore(release): v{version}` is whitelisted automatically.

## Pre-commit Hooks

Pre-commit hooks are required and run on every commit. Do NOT skip them with `--no-verify`. Hooks enforce:

- Secret detection (gitleaks)
- Lint + format (biome for TS, ruff for Python)
- Type checks (tsc for TS, ty for Python)
- Unit tests (vitest for TS, pytest for Python)
- Conventional commit prefix

## Pull Requests

- One logical change per PR
- Include tests for new code (target coverage >= 95%)
- Update `CLAUDE.md` or `README.md` if the change affects architecture or public API
- CI must pass (lint + test on Linux/Windows/macOS, Semgrep SAST, dependency review)

## Code of Conduct

This project follows the [Contributor Covenant 2.1](./CODE_OF_CONDUCT.md). By participating, you agree to uphold these standards.

## Security

If you find a security issue, do NOT open a public issue. Email `quangminh2402.dev@gmail.com` — see [SECURITY.md](./SECURITY.md).
