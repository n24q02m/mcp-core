# mcp-core

Unified MCP Streamable HTTP 2025-11-25 transport, OAuth 2.1 Authorization
Server, lifecycle management, install automation, and shared embedding
daemon for the n24q02m MCP ecosystem.

`mcp-core` is the **functional successor** to the archived
[`mcp-relay-core`](https://github.com/n24q02m/mcp-relay-core). All crypto,
storage, OAuth, relay, and schema modules from `mcp-relay-core` ship under
the same paths in `mcp-core` (1:1 superset), so downstream MCP servers can
migrate with a pure import + dependency rename. See
[`docs/migration-from-mcp-relay-core.md`](docs/migration-from-mcp-relay-core.md)
for the rename table.

## Packages

| Package | Language | Registry | Install |
|---------|----------|----------|---------|
| [`packages/core-py`](packages/core-py) | Python 3.13 | PyPI: [`n24q02m-mcp-core`](https://pypi.org/project/n24q02m-mcp-core/) | `pip install n24q02m-mcp-core` |
| [`packages/core-ts`](packages/core-ts) | TypeScript / Node 24 | npm: [`@n24q02m/mcp-core`](https://www.npmjs.com/package/@n24q02m/mcp-core) | `bun add @n24q02m/mcp-core` |
| [`packages/embedding-daemon`](packages/embedding-daemon) | Python 3.13 | PyPI: [`mcp-embedding-daemon`](https://pypi.org/project/mcp-embedding-daemon/) | `pip install mcp-embedding-daemon` |

All three packages share the same version (`semantic-release.toml` bumps both
Python `pyproject.toml` files plus the npm `package.json` in lockstep).

## What you get

### `n24q02m-mcp-core` (Python) and `@n24q02m/mcp-core` (TypeScript)

Identical public API in both languages:

- **`crypto/`** — ECDH P-256, AES-256-GCM, HKDF-SHA256 primitives.
  Cross-language test vectors guarantee Python and TypeScript produce the
  same ciphertext for the same input.
- **`storage/`** — encrypted config file (`config.enc`) backed by PBKDF2
  600k + machine-id key derivation, plus session lock files and config
  resolver helpers.
- **`oauth/`** — OAuth 2.1 Authorization Server building blocks: `JWTIssuer`
  (RS256), `OAuthProvider` (PKCE flow + relay session integration),
  `SqliteUserStore` for multi-user mode.
- **`relay/`** — `RelaySession`, `create_session`, `poll_for_result`,
  `send_message` plus the EFF Diceware wordlist for passphrase generation.
- **`schema/`** — `RelayConfigSchema` TypedDict that downstream servers use
  to declare their config form.
- **`transport/`** — `StreamableHTTPServer` wrapper around FastMCP /
  `@modelcontextprotocol/sdk` Streamable HTTP transport, plus
  `OAuthMiddleware` (RFC 6750 + RFC 9728 compliant Bearer validation).
- **`lifecycle/`** — `LifecycleLock` cross-platform file lock that prevents
  two server instances from binding the same `(name, port)` pair.
- **`install/`** (Python only) — `AgentInstaller` that writes MCP server
  entries into Claude Code, Cursor, Codex, Windsurf, and OpenCode config
  files.

### `mcp-embedding-daemon`

FastAPI HTTP server scaffold for the upcoming shared ONNX/GGUF embedding
backend. Currently exposes:

- `GET /health` — returns `{status, version}`
- `POST /embed` — returns 501 with a roadmap link (backend wiring lands in
  the next release)
- `POST /rerank` — returns 501 with a roadmap link

CLI entry point: `mcp-embedding-daemon --host 127.0.0.1 --port 9800`.

## Quick start (Python)

```python
from mcp_core import RelaySession, create_session, decrypt
from mcp_core.transport.streamable_http import StreamableHTTPServer
from mcp_core.oauth import JWTIssuer
from mcp_core.transport.oauth_middleware import OAuthMiddleware
from fastmcp import FastMCP

mcp = FastMCP("my-server")

issuer = JWTIssuer("my-server")
issuer  # Use issuer.issue_access_token(sub) / verify_access_token(token)

middleware = [OAuthMiddleware(issuer=issuer, resource_metadata_url="http://127.0.0.1:9876/.well-known/oauth-protected-resource")]
server = StreamableHTTPServer(mcp, port=9876, middleware=middleware)
server.run()
```

## Quick start (TypeScript)

```typescript
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { JWTIssuer } from '@n24q02m/mcp-core/oauth'
import { OAuthMiddleware, StreamableHTTPServer } from '@n24q02m/mcp-core/transport'

const server = new McpServer({ name: 'my-server', version: '0.0.0' })
const issuer = new JWTIssuer('my-server')
await issuer.init()

const middleware = new OAuthMiddleware({
  jwtIssuer: issuer,
  resourceMetadataUrl: 'http://127.0.0.1:9876/.well-known/oauth-protected-resource'
})

const http = new StreamableHTTPServer({ server, port: 9876, oauthMiddleware: middleware })
await http.connect()
// Then mount http.handleRequest(req, res) on your http.Server / Express / Hono.
```

## Documentation

Full docs at **[mcp.n24q02m.com/servers/mcp-core/](https://mcp.n24q02m.com/servers/mcp-core/)** (Foundation library section in the MCP n24q02m unified docs site):

- [Architecture](https://mcp.n24q02m.com/servers/mcp-core/architecture/) -- transport, OAuth AS, lifecycle, multi-user primitives
- [Trust model](https://mcp.n24q02m.com/servers/mcp-core/trust-model/) -- threat model + key-handling guarantees
- [Migration](https://mcp.n24q02m.com/servers/mcp-core/migration/) -- breaking-change history and upgrade paths from `mcp-relay-core`
- [Shared services](https://mcp.n24q02m.com/servers/mcp-core/shared-services/) -- embedding daemon + ancillary docker-compose stack

Source of truth lives in [`n24q02m/claude-plugins/plugins/mcp-core/`](https://github.com/n24q02m/claude-plugins/tree/main/plugins/mcp-core). Edit there; this repo's `docs/` directory is intentionally minimal post-migration.

## Development

```bash
mise run setup            # install runtimes + deps + pre-commit hooks
bun install               # root TypeScript workspace install

# Python (per package)
cd packages/core-py
uv sync --group dev
uv run pytest
uv run ty check
uv run ruff check .

# TypeScript
cd packages/core-ts
bun run test
bun run check
bun run build
```

## License

MIT
