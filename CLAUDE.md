# CLAUDE.md - mcp-core

Unified MCP Streamable HTTP 2025-11-25 transport, OAuth 2.1 Authorization Server, lifecycle management, install automation, và shared embedding daemon cho toàn bộ hệ sinh thái MCP n24q02m.

Supersedes (kế thừa) repo archived `mcp-relay-core`. Module mapping documented in `docs/migration-from-mcp-relay-core.md`.

## Monorepo

- `packages/core-py` — Python library (PyPI: `n24q02m-mcp-core`). Transport, OAuth 2.1 AS, lifecycle, install, crypto, config storage. Backend cho wet, mnemo, crg, telegram.
- `packages/core-ts` — TypeScript library (npm: `@n24q02m/mcp-core`). Parity với core-py. Backend cho email, notion.
- `packages/embedding-daemon` — Shared ONNX/GGUF embedding server (PyPI: `mcp-embedding-daemon`). Serves wet + mnemo + crg.
- `packages/stdio-proxy` — Thin stdio-to-HTTP forwarder (PyPI: `mcp-stdio-proxy`). Dùng cho agents thiếu HTTP support.

## Commands

### TypeScript (core-ts)
```
bun install                    # Install all TS deps (root workspace)
cd packages/core-ts
bun run test                   # vitest
bun run test:coverage          # vitest + coverage
bun run check                  # Biome + tsc --noEmit
bun run build                  # tsc build
```

### Python (core-py, embedding-daemon, stdio-proxy)
```
cd packages/<package>
uv sync --group dev            # Install Python deps
uv run pytest                  # Run tests
uv run pytest --cov            # Tests với coverage
uv run ruff check .            # Lint
uv run ruff format --check .   # Format check
uv run ty check                # Type check
```

### Setup toàn bộ monorepo
```
mise run setup                 # Install tools + deps + pre-commit hooks
```

## Architecture

- `packages/core-py/`: Python implementation — transport (Streamable HTTP), OAuth 2.1 AS, lifecycle, install, crypto (ECDH P-256 + AES-256-GCM), config storage (platformdirs).
- `packages/core-ts/`: TypeScript parity với core-py. Crypto output phải identical cho cùng inputs.
- `packages/embedding-daemon/`: FastAPI + ONNX runtime. Serves embedding inference cho các MCP servers cần embeddings (wet, mnemo, crg).
- `packages/stdio-proxy/`: httpx-based forwarder. Dùng khi agent không support HTTP transport.

## Release & Deploy

- Conventional Commits (feat: / fix: only). Tag format: `v{version}` (config: `semantic-release.toml`)
- CD: `workflow_dispatch`, chọn beta/stable
- Pipeline: PSR v10 -> npm publish (core-ts) + PyPI publish (core-py, embedding-daemon, stdio-proxy)
- Tất cả packages share cùng version. PSR bumps `packages/core-py/pyproject.toml`, `packages/embedding-daemon/pyproject.toml`, `packages/stdio-proxy/pyproject.toml` (version_toml). CD injects version vào `packages/core-ts/package.json` trước khi npm publish.
- Publishing: PyPI trusted publishers (pending publisher đã config cho 3 packages) + npm trusted publisher (sau lần publish đầu với NPM OIDC).
- Docker: chưa có (v0.1.0 library-only). Sẽ thêm sau khi embedding-daemon production-ready.

## Secrets (skret + AWS SSM)

- skret SSM namespace: `/mcp-core/prod` (region `ap-southeast-1`)
- CI: `skret env -e prod --path=/mcp-core/prod --format=dotenv >> $GITHUB_ENV`
- Local dev: `skret run -e prod -- <cmd>` (uses AWS credential chain)

## Security

- Crypto output parity giữa core-ts và core-py (test vectors)
- Pre-commit hooks: gitleaks (secret detection), biome (TS), ruff (Python), enforce-commit (feat/fix only)
- GitHub Actions SHA-pinned
- Semgrep SAST trên PR + push (private repo convention: Semgrep thay CodeQL)
- Dependency review fail-on-severity: moderate

## References

- Spec: `docs/superpowers/specs/2026-04-10-mcp-core-unified-transport-design.md` (trong repo claude-plugins)
- Archived predecessor: https://github.com/n24q02m/mcp-relay-core
