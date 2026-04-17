# Migration from mcp-relay-core to mcp-core

`mcp-core` is a functional **superset** of the now-archived
[`mcp-relay-core`](https://github.com/n24q02m/mcp-relay-core). The Python and
TypeScript public layouts are 1:1, so migrating a downstream server is a pure
import + dependency rename. Every symbol that lived in `mcp_relay_core.*` (or
`@n24q02m/mcp-relay-core/*`) lives at the same path under `mcp_core.*` (or
`@n24q02m/mcp-core/*`).

## Why migrate

- `mcp-relay-core` is **archived** as of 2026-04-11. No new releases.
- `mcp-core` adds the unified Streamable HTTP 2025-11-25 transport, OAuth 2.1
  Bearer middleware, lifecycle locks, install/agents config writer, and the
  shared embedding-daemon + stdio-proxy packages.
- All existing crypto / storage / OAuth / relay / schema modules are preserved
  byte-for-byte (with the package name substitution), so behavior is identical.

## Python (`packages/core-py`)

### Import rewrites

| Old (mcp-relay-core)                 | New (mcp-core)               |
|--------------------------------------|------------------------------|
| `from mcp_relay_core import X`       | `from mcp_core import X`     |
| `from mcp_relay_core.crypto.aes`     | `from mcp_core.crypto.aes`   |
| `from mcp_relay_core.crypto.ecdh`    | `from mcp_core.crypto.ecdh`  |
| `from mcp_relay_core.crypto.kdf`     | `from mcp_core.crypto.kdf`   |
| `from mcp_relay_core.storage.config_file`   | `from mcp_core.storage.config_file`  |
| `from mcp_relay_core.storage.encryption`    | `from mcp_core.storage.encryption`   |
| `from mcp_relay_core.storage.machine_id`    | `from mcp_core.storage.machine_id`   |
| `from mcp_relay_core.storage.mode`          | `from mcp_core.storage.mode`         |
| `from mcp_relay_core.storage.resolver`      | `from mcp_core.storage.resolver`     |
| `from mcp_relay_core.storage.session_lock`  | `from mcp_core.storage.session_lock` |
| `from mcp_relay_core.oauth import ...`      | `from mcp_core.oauth import ...`     |
| `from mcp_relay_core.relay.client`          | `from mcp_core.relay.client`         |
| `from mcp_relay_core.relay.browser`         | `from mcp_core.relay.browser`        |
| `from mcp_relay_core.relay.wordlist`        | `from mcp_core.relay.wordlist`       |
| `from mcp_relay_core.schema.types`          | `from mcp_core.schema.types`         |

In most server codebases this is a single sed command:

```bash
grep -rl "mcp_relay_core" src tests | xargs sed -i 's/mcp_relay_core/mcp_core/g'
```

### Dependency rename

`pyproject.toml`:

```diff
 [project]
 dependencies = [
-    "mcp-relay-core>=1.4.0",
+    "n24q02m-mcp-core>=1.0.0",
 ]
```

Note the PyPI package name is `n24q02m-mcp-core` (not `mcp-core`), but the
import path stays `mcp_core`.

After the rename, run `uv lock --upgrade-package n24q02m-mcp-core` (or your
project's lockfile equivalent) and commit.

### API changes you might notice

The Python port is byte-faithful with **two intentional bug fixes** that
surfaced under mcp-core's stricter `ty` type-check:

1. `mcp_core.relay.client.create_session(...)` now accepts an optional
   keyword-only `oauth_state: dict[str, str] | None = None` parameter. When
   non-None it is forwarded to the relay-server as `oauthState` in the POST
   body. Existing callers that did not pass `oauth_state` are unaffected.
2. `mcp_core.relay.client.RelaySession.public_key` is now
   `EllipticCurvePublicKey | None` instead of `EllipticCurvePublicKey`. This
   restores the documented "decrypt-only reconstructed session" use case in
   `OAuthProvider.exchange_code()`. No callers in mcp-relay-core read this
   field, so existing code is unaffected.

These two fixes lived as latent bugs in `mcp-relay-core/oauth/provider.py` —
that file referenced API signatures that did not exist in
`mcp-relay-core/relay/client.py`. The OAuth Provider was apparently never
exercised end-to-end on the Python side.

## TypeScript (`packages/core-ts`)

### Import rewrites

| Old (`@n24q02m/mcp-relay-core`) | New (`@n24q02m/mcp-core`) |
|---------------------------------|---------------------------|
| `from '@n24q02m/mcp-relay-core'`         | `from '@n24q02m/mcp-core'`         |
| `from '@n24q02m/mcp-relay-core/crypto'`  | `from '@n24q02m/mcp-core/crypto'`  |
| `from '@n24q02m/mcp-relay-core/storage'` | `from '@n24q02m/mcp-core/storage'` |
| `from '@n24q02m/mcp-relay-core/relay'`   | `from '@n24q02m/mcp-core/relay'`   |
| `from '@n24q02m/mcp-relay-core/schema'`  | `from '@n24q02m/mcp-core/schema'`  |
| `from '@n24q02m/mcp-relay-core/oauth'`   | `from '@n24q02m/mcp-core/oauth'`   |

Single sed command:

```bash
grep -rl "@n24q02m/mcp-relay-core" src tests | xargs sed -i 's|@n24q02m/mcp-relay-core|@n24q02m/mcp-core|g'
```

### Dependency rename

`package.json`:

```diff
 "dependencies": {
-  "@n24q02m/mcp-relay-core": "^1.1.0"
+  "@n24q02m/mcp-core": "^1.0.0"
 }
```

Run `bun install` (or `pnpm install` / `npm install`) and commit the lockfile.

## New features available (opt-in)

Once migrated, you can adopt these without further breaking changes:

- `mcp_core.transport.streamable_http.StreamableHTTPServer` and
  `@n24q02m/mcp-core/transport`'s `StreamableHTTPServer` — thin wrappers
  around the FastMCP / `@modelcontextprotocol/sdk` transports that integrate
  the lifecycle lock and OAuth middleware out of the box.
- `mcp_core.transport.oauth_middleware.OAuthMiddleware` (Python) /
  `OAuthMiddleware` (TypeScript) — RFC 6750 + RFC 9728 compliant Bearer token
  validation that returns 401 with
  `WWW-Authenticate: Bearer resource_metadata="..."`.
- `mcp_core.lifecycle.lock.LifecycleLock` — cross-platform file lock that
  prevents two server instances from binding the same `(name, port)` pair.
  Stores PID + port as readable metadata while the lock is held.
- `mcp_core.install.agents.AgentInstaller` — write or remove an MCP server
  entry in agent config files (Claude Code, Cursor, Codex, Windsurf, OpenCode).
- `mcp-embedding-daemon` PyPI package — shared FastAPI server scaffold for
  the upcoming ONNX/GGUF embedding backend. Exposes `/health` and
  scaffolded `/embed` + `/rerank` (501 with roadmap link).
- `mcp-stdio-proxy` PyPI package — `mcp-stdio-proxy` CLI that forwards
  stdio MCP frames to an HTTP MCP server, for agents without native HTTP.

## Verification checklist

After applying the rename in your downstream repo:

- [ ] `grep -rn "mcp_relay_core\|mcp-relay-core\|@n24q02m/mcp-relay-core" src tests` returns nothing
- [ ] `pyproject.toml` no longer references `mcp-relay-core`
- [ ] `package.json` no longer references `@n24q02m/mcp-relay-core`
- [ ] Lockfile regenerated and committed
- [ ] Test suite passes
- [ ] Lint + type check pass

If anything breaks, please open an issue at
<https://github.com/n24q02m/mcp-core/issues> with the error message and the
rename diff.
