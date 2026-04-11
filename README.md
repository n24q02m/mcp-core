# mcp-core

Unified MCP Streamable HTTP 2025-11-25 transport, OAuth 2.1 Authorization Server, lifecycle management, install automation, and shared embedding daemon for the n24q02m MCP ecosystem.

## Packages

- `packages/core-py` — Python implementation (wet, mnemo, crg, telegram backends)
- `packages/core-ts` — TypeScript implementation (email, notion backends)
- `packages/embedding-daemon` — Shared ONNX/GGUF embedding server (serves wet + mnemo + crg)
- `packages/stdio-proxy` — Thin stdio-to-HTTP forwarder for agents without HTTP support

## Supersedes

Replaces the archived [mcp-relay-core](https://github.com/n24q02m/mcp-relay-core) repository. Module mapping documented in `docs/migration-from-mcp-relay-core.md`.

## Spec

Architecture design lives in [claude-plugins/docs/superpowers/specs/2026-04-10-mcp-core-unified-transport-design.md](https://github.com/n24q02m/claude-plugins/blob/feat/phase3-mcp-core-unified/docs/superpowers/specs/2026-04-10-mcp-core-unified-transport-design.md).

## License

MIT
