# mcp-core

**Shared foundation for building MCP servers -- Streamable HTTP transport, OAuth 2.1, browser-based credential setup, and a shared embedding daemon.**

<!-- BEGIN: AUTO-GENERATED-CROSS-PROMO -->
<details>
  <summary><strong>Sister projects from n24q02m</strong> (click to expand)</summary>

| Project | Tagline | Tag |
|---|---|---|
| [agent-chat-plugin](https://github.com/n24q02m/agent-chat-plugin) | Peer AI agents chat in a shared folder — no human relay, no orchestrator, wor... | Tooling |
| [better-code-review-graph](https://github.com/n24q02m/better-code-review-graph) | Knowledge graph for token-efficient code reviews -- semantic search and call-... | MCP |
| [better-drive](https://github.com/n24q02m/better-drive) | 2-way Google Drive sync with .driveignore filter — rclone engine, Windows tray | Tooling |
| [better-email-mcp](https://github.com/n24q02m/better-email-mcp) | IMAP/SMTP email for AI agents -- read, send, organize folders, and manage att... | MCP |
| [better-godot-mcp](https://github.com/n24q02m/better-godot-mcp) | Composite MCP server for Godot Engine -- 17 composite tools for AI-assisted g... | MCP |
| [better-notion-mcp](https://github.com/n24q02m/better-notion-mcp) | Markdown-first Notion for AI agents -- pages, databases, blocks, and comments... | MCP |
| [better-semantic-release](https://github.com/n24q02m/better-semantic-release) | Drop-in python-semantic-release fork with built-in release-safety guards (orp... | Tooling |
| [better-telegram-mcp](https://github.com/n24q02m/better-telegram-mcp) | Telegram for AI agents -- messages, chats, media, and contacts across both bo... | MCP |
| [better-workspace-mcp](https://github.com/n24q02m/better-workspace-mcp) | Google Workspace MCP server (Docs/Drive/Calendar/Gmail/Sheets/Slides/Tasks/Ch... | MCP |
| [claude-plugins](https://github.com/n24q02m/claude-plugins) | Claude Code plugin marketplace for the n24q02m MCP servers -- install web sea... | Marketplace |
| [imagine-mcp](https://github.com/n24q02m/imagine-mcp) | Image and video understanding + generation for AI agents -- across Gemini, Op... | MCP |
| [jules-task-archiver](https://github.com/n24q02m/jules-task-archiver) | Chrome Extension for bulk operations on Jules tasks via batchexecute API -- a... | Tooling |
| [mcp-core](https://github.com/n24q02m/mcp-core) | Shared foundation for building MCP servers -- Streamable HTTP transport, OAut... | MCP |
| [mnemo-mcp](https://github.com/n24q02m/mnemo-mcp) | Persistent AI memory with hybrid search and embedded sync. Open, free, unlimi... | MCP |
| [qwen3-embed](https://github.com/n24q02m/qwen3-embed) | Lightweight Qwen3 text embedding and reranking via ONNX Runtime and GGUF | Library |
| [skret](https://github.com/n24q02m/skret) | Secrets without the server. | CLI |
| [tacet](https://github.com/n24q02m/tacet) | A self-distilling neuro-symbolic cascade that amortises LLM cost across knowl... | Tooling |
| [web-core](https://github.com/n24q02m/web-core) | Shared web infrastructure package for search, scraping, HTTP security, and st... | Library |
| [wet-mcp](https://github.com/n24q02m/wet-mcp) | Open-source MCP server for AI agents: web search, content extraction, and lib... | MCP |

</details>
<!-- END: AUTO-GENERATED-CROSS-PROMO -->

## Table of contents

- [Packages](#packages)
- [What you get](#what-you-get)
- [Quick start (Python)](#quick-start-python)
- [Quick start (TypeScript)](#quick-start-typescript)
- [CLI](#cli)
- [Documentation](#documentation)
- [Development](#development)
- [License](#license)



mcp-core is the shared foundation for the n24q02m MCP servers: a Streamable
HTTP transport, an OAuth 2.1 Authorization Server, lifecycle management,
install automation, and a shared embedding daemon.

`mcp-core` is the **functional successor** to the archived
[`mcp-relay-core`](https://github.com/n24q02m/mcp-relay-core). All crypto,
storage, OAuth, relay, and schema modules from `mcp-relay-core` ship under
the same paths in `mcp-core` (1:1 superset), so downstream MCP servers can
migrate with a pure import + dependency rename. See the
[Migration guide](https://mcp.n24q02m.com/servers/mcp-core/migration/)
for the rename table.

## Packages

| Package | Language | Registry | Install |
|---------|----------|----------|---------|
| [`packages/core-py`](packages/core-py) | Python 3.13 | PyPI: [`n24q02m-mcp-core`](https://pypi.org/project/n24q02m-mcp-core/) | `pip install n24q02m-mcp-core` |
| [`packages/core-ts`](packages/core-ts) | TypeScript / Node 24 | npm: [`@n24q02m/mcp-core`](https://www.npmjs.com/package/@n24q02m/mcp-core) | `bun add @n24q02m/mcp-core` |
| [`packages/embedding-daemon`](packages/embedding-daemon) | Python 3.13 | PyPI: [`mcp-embedding-daemon`](https://pypi.org/project/mcp-embedding-daemon/) | `pip install mcp-embedding-daemon` |

All three packages share the same version (`semantic-release.toml` bumps both
Python `pyproject.toml` files plus the npm `package.json` in lockstep).

The Python core ships one optional extra for the LLM passthrough (litellm):
`pip install 'n24q02m-mcp-core[llm]'`.

## What you get

### `n24q02m-mcp-core` (Python) and `@n24q02m/mcp-core` (TypeScript)

These modules ship in **both** languages with a matching public API
(cross-language test vectors keep the crypto byte-for-byte identical):

- **`crypto/`** — ECDH P-256, AES-256-GCM, HKDF-SHA256 primitives.
  Cross-language test vectors guarantee Python and TypeScript produce the
  same ciphertext for the same input.
- **`storage/`** — `PerPluginStore`, the per-plugin encrypted credential
  store. Single-user (stdio / HTTP) writes `~/.<plugin>-mcp/config.json`
  encrypted with a machine-bound key; HTTP multi-user writes
  `~/.<plugin>-mcp/subs/<sub>/config.json` encrypted with a key derived from
  the `CREDENTIAL_SECRET` env var (salt `<plugin>:<sub>`). Pluggable
  `CredentialBackend`s (`LocalFsBackend`, `CfKvBackend`) decouple the on-disk
  layout from serverless deployments. Also ships session lock files and
  config resolver helpers. The legacy shared `config.enc` file
  (`storage.config_file`) is deprecated.
- **`auth/`** — the self-hosted OAuth 2.1 Authorization Server that downstream
  servers actually run: `create_local_oauth_app` (Starlette ASGI app serving
  `/authorize`, `/token`, the `/.well-known/oauth-*` metadata, and the
  browser-rendered credential form), `render_credential_form`, the optional
  shared-password gate at `/login` (`MCP_RELAY_PASSWORD`, empty disables it),
  and `create_delegated_oauth_app` for upstream-redirect / device-code
  multi-user flows.
- **`oauth/`** — OAuth 2.1 primitives consumed by `auth/`: `JWTIssuer`
  (RS256), `SqliteUserStore` for multi-user mode, and `OAuthProvider`, the
  legacy `mcp-relay-core` PKCE-over-relay provider retained for migration.
- **`relay/`** — `RelaySession`, `create_session`, `poll_for_result`,
  `send_message` plus the EFF Diceware wordlist for passphrase generation.
  This is the legacy `mcp-relay-core` ECDH relay-client path used by
  `OAuthProvider`; the live setup UX is the `auth/` browser credential form.
- **`schema/`** — `RelayConfigSchema` TypedDict that downstream servers use
  to declare their config form.
- **`transport/`** — `StreamableHTTPServer` wrapper around FastMCP /
  `@modelcontextprotocol/sdk` Streamable HTTP transport, plus
  `OAuthMiddleware` (RFC 6750 + RFC 9728 compliant Bearer validation).
- **`lifecycle/`** — `LifecycleLock` cross-platform file lock that prevents
  two server instances from binding the same `(name, port)` pair.

### Python-only modules (`n24q02m-mcp-core`)

These have no TypeScript counterpart yet — they back the Python MCP servers
(wet, mnemo, code-review-graph, telegram, imagine):

- **`llm/`** — a thin passthrough over [litellm](https://github.com/BerriAI/litellm)
  so every server talks to cloud providers the same way. Async + sync wrappers
  for `completion`, `embedding`, `rerank`, `image_generation`,
  `video_generation` / `video_status` / `video_content`; a graceful capability
  check against the litellm registry (`check_capability`, `list_models`,
  `suggest_models`, `supports_vision`); multi-key CSV rotation per provider
  (`rotate_keys`, `split_keys`); and a direct Vertex AI **Express** adapter
  (`completion_express`) that bypasses litellm where its `vertex_ai/` route
  ignores the Express API key. Provider keys follow the litellm convention —
  `GEMINI_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY`, `ANTHROPIC_API_KEY`,
  `COHERE_API_KEY`, `JINA_AI_API_KEY`, `GOOGLE_VERTEX_EXPRESS_API_KEY` (see
  `llm.providers.PROVIDER_KEY_ENV`); any unlisted provider falls back to
  `<PROVIDER>_API_KEY`. Requires the optional extra:
  `pip install 'n24q02m-mcp-core[llm]'`.
- **`chains.py`** — the capability provider-chain primitive every server shares
  (exported at the top level): `resolve_backend` makes the 3-way
  cloud / local / unavailable decision, `run_with_fallback` walks an ordered
  list of providers and returns the first non-empty result, and
  `local_enabled_from_env` reads the per-capability `DISABLE_LOCAL_<X>` toggle
  (`DISABLE_LOCAL_SEARCH` / `DISABLE_LOCAL_BROWSER` / `DISABLE_LOCAL_EMBED` /
  `DISABLE_LOCAL_RERANK`).
- **`http/`** — SSRF-safe HTTP clients (`get_ssrf_safe_async_client`,
  `get_ssrf_safe_sync_client`, `vet_api_base`) that block requests to private /
  loopback / link-local addresses. Used to vet every user-supplied `api_base`
  before it reaches an outbound provider call.
- **`install/`** — `AgentInstaller` writes MCP server entries into Claude Code,
  Cursor, Codex, Windsurf, and OpenCode config files. Ships the
  `mcp-clean-state` console script for wiping local config / session state.

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

## CLI

`mcp_core.cli.build_cli` (re-exported as `from mcp_core import build_cli`) is the
console-script builder every Python MCP server mounts as its entry point. It wraps
a server's existing `serve(argv) -> int | None` function with subcommand dispatch,
so every server exposes the **same** operator subcommands for free while `serve`'s
own behaviour stays byte-for-byte unchanged. It has no TypeScript counterpart.

A downstream server mounts it as its console script:

```python
# wet_mcp/cli.py
from mcp_core import build_cli

def main() -> int:
    return build_cli("wet-mcp", serve=_serve, extra=_extras(), version=_version())(None)
```

```toml
# pyproject.toml
[project.scripts]
wet-mcp = "wet_mcp.cli:main"
```

### Dispatch rules

`build_cli(...)` returns `run(argv=None) -> int`, which inspects `argv[0]`:

- **No args** — start the server (`serve([])`), the normal stdio launch.
- **A flag** (`--http`, ...) — passed byte-for-byte to `serve`; existing flag
  semantics are untouched.
- **`-h` / `--help`** — print the subcommand list and exit without starting the
  server (which would otherwise hang waiting on stdin in stdio mode).
- **`--version` / `-V`** — print `<server> <version>`, but only when `version=` is
  passed; otherwise it falls through to `serve` like any other flag.
- **A positional name** — routed as a subcommand through argparse; an unknown name
  exits `2`.

STDOUT is the MCP protocol channel in stdio mode, so only the subcommand path prints
to stdout: informational results (status, session details, `doctor`'s
`[ok]`/`[warn]`/`[fail]` lines) go to stdout, while failures and prompts go to stderr
with a non-zero exit code. Credential **values** are never printed — only names, keys,
and status.

### Built-in subcommands

Every server gets three reserved subcommands without writing any code:

| Subcommand | Purpose |
|---|---|
| `config status` | Report whether a config is stored: `configured`, `not configured`, or `corrupt` (undecryptable). |
| `config delete [--yes]` | Delete the stored config. Prompts to confirm; `--yes` skips the prompt and is required in non-interactive mode. |
| `relay status` | Show the active relay session (id prefix, relay URL, age) or report that none is active. |
| `relay open` | Open the active relay URL in a browser. |
| `relay reset` | Clear the relay session lock and the stored transport mode. |
| `doctor` | Environment diagnostics — Python 3.13, credential-backend init, store-dir writability, config state, relay session, transport mode. Exits non-zero on any `[fail]`. |

```bash
wet-mcp doctor
wet-mcp config status
wet-mcp relay status
```

### Server-specific subcommands (`extra`)

`build_cli(..., extra=...)` adds server-specific subcommands. Names in `extra` take
precedence over the built-ins, so a server can replace `config` / `relay` / `doctor`
with its own wiring. Each `extra` value is one of two shapes:

```python
ExtraHandler = Callable[[argparse.Namespace], int]
ExtraSpec = ExtraHandler | tuple[Callable[[argparse.ArgumentParser], None], ExtraHandler]
```

- A **bare handler** — registered as an argument-less subcommand.
- A **`(configure, handler)` tuple** — `configure` receives that subcommand's own
  `argparse.ArgumentParser` to add positionals/flags before argv is parsed, then
  `handler` receives the parsed `Namespace` and returns the exit code.

wet-mcp, for example, registers one bare handler and two configured ones:

```python
extra = {
    "warmup": _handle_warmup,                 # wet-mcp warmup
    "auth": (_configure_auth, _handle_auth),  # wet-mcp auth google [--client-id ...]
    "docs": (_configure_docs, _handle_docs),  # wet-mcp docs reindex <library>
}
```

## Documentation

Full docs at **[mcp.n24q02m.com/servers/mcp-core/architecture/](https://mcp.n24q02m.com/servers/mcp-core/architecture/)** (Foundation library section in the MCP n24q02m unified docs site):

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
