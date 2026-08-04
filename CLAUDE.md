# CLAUDE.md - mcp-core

Unified MCP Streamable HTTP 2025-11-25 transport, OAuth 2.1 Authorization Server, lifecycle management, install automation, và shared embedding daemon cho toàn bộ hệ sinh thái MCP n24q02m.

Supersedes (kế thừa) repo archived `mcp-relay-core`. Module mapping documented at https://mcp.n24q02m.com/servers/mcp-core/migration/.

## Monorepo

- `packages/core-py` — Python library (PyPI: `n24q02m-mcp-core`). Transport, OAuth 2.1 AS, lifecycle, install, crypto, config storage. Backend cho wet, mnemo, crg, telegram.
- `packages/core-ts` — TypeScript library (npm: `@n24q02m/mcp-core`). Parity với core-py. Backend cho email, notion.
- `packages/embedding-daemon` — Shared ONNX/GGUF embedding server (PyPI: `mcp-embedding-daemon`). Serves wet + mnemo + crg.

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

### Python (core-py, embedding-daemon)
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

### Divergence ts/py CÓ CHỦ ĐÍCH (đừng "sửa parity")

Parity nghĩa là **cùng hành vi**, không phải cùng cách nối dây. Ba chỗ dưới đây khác nhau có lý do; ai định đồng nhất chúng thì đọc lý do trước.

| Chỗ | Trạng thái | Vì sao |
|---|---|---|
| `elicitation` | **GIỮ khác nhau** | ts nhận tham số `elicitation?: ElicitationServer`; py đọc `ctx.session`. Do framework: fastmcp inject `Context` nên py lấy tự nhiên, TS SDK không có cơ chế đó. Ép giống nhau làm một bên xấu đi, không ai lợi. |
| Banner `ACTION REQUIRED` khi mở browser thất bại | **GIỮ chỉ ở py** | Consumer Python chạy như CLI/daemon trong terminal người dùng nhìn thấy → banner stderr có tác dụng. Consumer TS chạy trong client MCP nơi stderr thường bị nuốt → banner chỉ là rác. KHÔNG thêm banner vào ts để "cho giống". |
| `extra_routes` | **NÊN đóng, nhưng chờ consumer thật** | Đây là khác biệt **năng lực**, không phải cư xử: `extraRoutes` có ở core-ts (`local-server.ts`), py không có đối ứng, nên consumer Python muốn sở hữu một route chỉ còn đường fork. Chưa làm vì chưa có call-site Python nào cần — viết API general-purpose cho một người dùng tưởng tượng là đúng cái bẫy `registerOpenRelayTool` đã dính (0 consumer TS gọi nó). Có consumer Python thật thì đóng ngay. |

## Release & Deploy

- Conventional Commits (feat: / fix: only). Tag format: `v{version}` (config: `semantic-release.toml`)
- CD: `workflow_dispatch`, chọn beta/stable
- Pipeline: PSR v10 -> npm publish (core-ts) + PyPI publish (core-py, embedding-daemon)
- Gate trước khi dispatch: phát hành từ `main`, working tree sạch, các kiểm tra CI và E2E bắt buộc đã xanh, không còn PR actionable đang mở, và không có alert mở của Dependabot, code scanning hoặc secret scanning. Issue Dependency Dashboard thường trực là allowlist duy nhất. Không bypass gate hoặc bỏ qua backlog lỗi.
- Stable còn cần beta cascade và Test B client matrix pass trên beta đã publish bằng tool call thật; T0 CI/E2E không thay thế được Test B.
- Job release chạy PSR dry-run và kiểm tra version được tính có bị trùng trên npm cùng hai package PyPI hay không trước khi tạo tag/GitHub Release. Các job publish chỉ chạy khi PSR trả về `released=true`.
- `beta`: PSR chạy prerelease với token `beta`, npm dùng dist-tag `beta`; không tạo issue bump cho downstream.
- `stable`: PSR chạy stable release, npm dùng dist-tag `latest`. Chỉ sau khi release, npm publish và cả hai PyPI publish thành công thì CD mới tạo issue downstream.
- Stable-only downstream fan-out trong `.github/workflows/cd.yml`:
  - Issue bump pin npm cho `better-notion-mcp`, `better-email-mcp`, `better-godot-mcp`, `better-workspace-mcp` với package `@n24q02m/mcp-core`.
  - Issue bump pin PyPI cho `better-telegram-mcp`, `wet-mcp`, `mnemo-mcp`, `better-code-review-graph`, `imagine-mcp` với package `n24q02m-mcp-core`.
  - Issue tracking cho `qwen3-embed`, `web-core`, `claude-plugins` để kiểm tra reference tích hợp mcp-core hoặc marketplace.
- Job downstream tìm issue hiện có trước khi tạo mới. Issue pin trực tiếp yêu cầu cập nhật dependency và lockfile; issue tracking có thể đóng kèm kết quả kiểm tra nếu repo không có reference cần đổi.
- Tất cả packages share cùng version. PSR bumps `packages/core-py/pyproject.toml`, `packages/embedding-daemon/pyproject.toml` (version_toml). CD injects version vào `packages/core-ts/package.json` trước khi npm publish.
- Publishing: PyPI trusted publishers (pending publisher đã config cho 2 packages) + npm trusted publisher (sau lần publish đầu với NPM OIDC).
- Docker: không có image. mcp-core là library (core-py / core-ts / embedding-daemon) — consume qua PyPI/npm bởi downstream MCP servers, không ship CLI/daemon runnable riêng.

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
