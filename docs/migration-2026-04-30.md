# Migration Guide: mcp-core 1.12.0 — Multi-Mode (stdio + HTTP) Architecture

**Audience:** users of `n24q02m-mcp-core` / `@n24q02m/mcp-core` and any of the
8 downstream MCP plugins (wet, mnemo, better-code-review-graph, imagine,
better-telegram, better-notion, better-email, better-godot).

**Effective:** mcp-core 1.12.0 onward. Smart_stdio bridge for stdio path is
soft-deprecated in this release and scheduled for hard removal in 2.0.0.

---

## What changed

mcp-core 1.12.0 deprecates the **smart_stdio bridge layer** for stdio mode.
Previously, every stdio-mode invocation of an MCP plugin spawned a long-running
HTTP daemon plus a thin stdio-to-HTTP proxy that forwarded JSON-RPC frames
between Claude Code (or any MCP client) and the daemon. The bridge proxy
maintained lock files, capabilities caches, sentinel files, and a heartbeat
respawn loop.

Starting in 1.12.0, **plugins run as standard FastMCP stdio servers directly**
when `MCP_TRANSPORT=stdio` is set. There is no bridge layer, no daemon, no
lock files, and no capabilities cache for the stdio path.

The HTTP daemon mode is **preserved unchanged** for multi-user / hosted
scenarios (better-notion, better-email, better-telegram default to remote
HTTP). Only the entry-point wrapper renamed `run_local_server` →
`run_http_daemon`; an alias keeps existing callers working.

**Why:** the bridge layer added 3 P0 incidents in the last 30 days
(spawn fork-bomb, spam-tabs, 22-process leak) and silently broke tool
registration on 5 of 8 plugins (Test B incident 2026-04-30). The direct
FastMCP stdio path is what every other MCP-compatible client (Cursor,
VS Code Copilot, Windsurf, Continue.dev, Cline) expects.

---

## User action required

After upgrading mcp-core to 1.12.0, run the cleanup CLI **once** to
terminate any leftover bridge daemons and remove their lock + cache
state:

```bash
mcp-clean-state --kill-daemons
```

This:

1. Iterates every `*.lock` file under `~/.config/mcp/locks/`
   (or `%LOCALAPPDATA%\mcp\locks\` on Windows).
2. Parses the daemon PID from line 0 of each lock.
3. If the PID is alive, terminates the process (cross-platform: SIGKILL
   on POSIX, `TerminateProcess` on Windows).
4. Removes the `*.lock` file plus matching `*.tools.json` companion in
   the cache directory and any `*.tools-list-changed` sentinel.

Output:

```
Killed N daemons; cleaned M lock files.
```

If you skip this step, leftover bridge daemons continue to listen on their
random ports (harmless but wasteful) until the next reboot or 24h TTL sweep.
The next stdio plugin invocation does **not** consult these old daemons —
it spawns a new direct FastMCP stdio process instead — so there is no
correctness risk, only resource leak.

---

## New plugin manifest patterns

The 8 plugins split into two default modes after migration:

| Default mode | Plugins | Reason |
|---|---|---|
| stdio | wet, mnemo, better-code-review-graph, imagine, better-godot | local-only credentials (Google Drive, SQLite, Godot project files); no multi-user need |
| HTTP remote | better-notion, better-email, better-telegram | per-user OAuth tokens managed by hosted instance; multi-user out of the box |

Self-hosting alternatives are available for every plugin via Docker images
tagged `:stdio` and `:http` per plugin.

### Mode 1 — stdio via uvx (default for 5 Python plugins)

For Claude Code (`~/.claude/plugins/<plugin>/.claude-plugin/plugin.json`),
VS Code Copilot (`~/.config/copilot/mcp.json`), Cursor (`~/.cursor/mcp.json`),
Windsurf, Continue.dev — **identical shape**:

```json
{
  "mcpServers": {
    "wet": {
      "command": "uvx",
      "args": ["--python", "3.13", "wet-mcp"],
      "env": {"MCP_TRANSPORT": "stdio"}
    }
  }
}
```

Replace `wet` / `wet-mcp` with the relevant plugin (see plugin's README for
its short name).

### Mode 2 — stdio via npx (default for better-godot)

```json
{
  "mcpServers": {
    "better-godot-mcp": {
      "command": "npx",
      "args": ["-y", "@n24q02m/better-godot-mcp"],
      "env": {"MCP_TRANSPORT": "stdio"}
    }
  }
}
```

### Mode 3 — stdio via Docker (self-host, any plugin)

When you cannot install uvx/npx on the client machine (e.g. locked-down
corporate laptop, but Docker is available):

```json
{
  "mcpServers": {
    "wet": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "n24q02m/wet-mcp:stdio"],
      "env": {"MCP_TRANSPORT": "stdio"}
    }
  }
}
```

### Mode 4 — HTTP remote (default for notion, email, telegram)

n24q02m-hosted instance, no setup required beyond OAuth in the browser:

```json
{
  "mcpServers": {
    "better-notion-mcp": {
      "url": "https://better-notion-mcp.n24q02m.com/mcp",
      "transport": "http"
    }
  }
}
```

Same shape for `better-email-mcp.n24q02m.com` and
`better-telegram-mcp.n24q02m.com`.

### Mode 5 — HTTP self-hosted (any plugin)

For data-residency or air-gapped environments:

```bash
docker run -d -p 8001:8000 \
  -e PUBLIC_URL=http://localhost:8001 \
  -e MCP_DCR_SERVER_SECRET=$(openssl rand -hex 32) \
  n24q02m/better-notion-mcp:http
```

Then point the manifest to `http://localhost:8001/mcp`.

---

## Plugin developer guidance

If you import `mcp_core` (Python) or `@n24q02m/mcp-core` (TypeScript) inside
your own plugin code, the API surface changes are:

### Python — API kept

| Symbol | Status | Notes |
|---|---|---|
| `mcp_core.transport.run_http_daemon` | NEW (1.12.0) | Renamed from `run_local_server`; alias preserved. |
| `mcp_core.transport.run_local_server` | KEPT (alias) | Calls `run_http_daemon`. Still works in 1.x. |
| `mcp_core.config.*` | KEPT | Config storage primitives (`load_config`, `save_config`, `config.enc`). |
| `mcp_core.crypto.*` | KEPT | ECDH P-256 + AES-256-GCM helpers. |
| `mcp_core.relay.register_relay_form_tool` | NEW (1.12.0) | Transient HTTP relay form for stdio-mode credential setup. |
| `mcp_core.lifecycle.*` | KEPT | Lock file primitives still used by HTTP daemon mode. |
| `mcp_core.install.*` | KEPT | Plugin installer helpers. |

### Python — API deprecated (removed in 2.0.0)

| Symbol | Replacement |
|---|---|
| `mcp_core.transport.run_smart_stdio_proxy` | `mcp.run(transport="stdio")` directly inside the plugin's `main()`. Emits `DeprecationWarning` from 1.12.0. |
| `mcp_core.transport.persist_capabilities_cache` | No replacement — the `<lock>.tools.json` cache is no longer written for stdio path. HTTP daemon mode never used it. |
| Sentinel polling helpers (`watch_tools_list_changed`) | No replacement — sentinel auto-respawn was a stdio-bridge implementation detail. |

### TypeScript — API kept

| Symbol | Status | Notes |
|---|---|---|
| `runHttpDaemon` | NEW (1.12.0) | Renamed from `runLocalServer`; alias preserved. |
| `runLocalServer` | KEPT (alias) | Calls `runHttpDaemon`. |
| `loadConfig` / `saveConfig` | KEPT | Config storage. |
| `EcdhAesCrypto` | KEPT | Crypto parity with Python. |

### TypeScript — API deprecated (removed in 2.0.0)

| Symbol | Replacement |
|---|---|
| `runSmartStdioProxy` | `new StdioServerTransport()` from `@modelcontextprotocol/sdk/server/stdio.js`, then `await server.connect(transport)`. Emits deprecation warning. |

### Migration template — Python `main()`

Before (mcp-core ≤1.11):

```python
import os
import sys

from mcp_core.transport import run_smart_stdio_proxy

def main() -> None:
    if "--stdio" in sys.argv or os.environ.get("MCP_TRANSPORT") == "stdio":
        daemon_cmd = [sys.executable, "-m", "wet_mcp"]
        sys.exit(run_smart_stdio_proxy("wet-mcp", daemon_cmd))
    # ... HTTP path unchanged
```

After (mcp-core ≥1.12):

```python
import os
import sys

from wet_mcp.server import mcp  # Your FastMCP instance

def main() -> None:
    if "--stdio" in sys.argv or os.environ.get("MCP_TRANSPORT") == "stdio":
        # Direct FastMCP stdio — no bridge, no daemon, no lock file.
        # Universal MCP client compatibility.
        mcp.run(transport="stdio")
        return
    # ... HTTP path unchanged
```

### Migration template — TypeScript `main.ts`

Before:

```ts
import { runSmartStdioProxy } from '@n24q02m/mcp-core'

if (process.env.MCP_TRANSPORT === 'stdio') {
  const exit = await runSmartStdioProxy('better-notion-mcp', [process.argv[0], ...process.argv.slice(1)])
  process.exit(exit)
}
```

After:

```ts
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'

if (process.env.MCP_TRANSPORT === 'stdio') {
  const transport = new StdioServerTransport()
  await server.connect(transport)
  return
}
```

### Relay form for stdio-mode credential setup

If your plugin requires user credentials (e.g. an API key or OAuth flow)
and you are migrating to stdio mode, register the transient relay form
helper so users can configure credentials via a local browser tab:

```python
from mcp_core.relay import register_relay_form_tool
from wet_mcp.config import save_credentials  # Your callback

register_relay_form_tool(
    mcp,
    server_name="wet-mcp",
    on_save=save_credentials,  # Called with (server_name, creds_dict)
)
```

The helper registers a tool named `config__open_relay`. When the user
invokes that tool, the plugin spawns an in-process HTTP server on a
random local port, opens the user's browser to a credential form,
and self-shutdowns after submission or 10 minutes idle.

---

## Migration timeline

| Version | Date | smart_stdio status |
|---|---|---|
| 1.11.x | pre-2026-04-30 | Active code path; default stdio mode. |
| **1.12.0** | **2026-04-30** | **Deprecated** for stdio path. `run_smart_stdio_proxy` emits `DeprecationWarning`. Alias still works. New stdio path uses direct FastMCP. |
| 1.13.0 — 1.x | future minors | Alias preserved. Deprecation warning still emitted. |
| 2.0.0 | next major | `run_smart_stdio_proxy` and the entire `smart_stdio.py` module **removed**. `<lock>.tools.json` cache logic removed. Sentinel polling removed. |

Plugins must migrate stdio-mode entry points to direct FastMCP / SDK calls
before 2.0.0 ships.

---

## Troubleshooting

### "ToolSearch finds nothing" after upgrade

Confirm:

1. `mcp-clean-state --kill-daemons` was run (kills leftover bridge daemons).
2. Restart your MCP client (Claude Code, Cursor, etc.) so it re-spawns the
   plugin process and re-discovers tools.
3. The plugin's manifest does **not** point at an old `n24q02m/<plugin>:latest`
   Docker image — pull `:stdio` or `:http` explicitly.

### "DeprecationWarning: run_smart_stdio_proxy"

Expected if you have a third-party plugin still using the old bridge import.
The plugin still works in 1.x; track its upgrade and pin to a 1.x mcp-core
release if you cannot wait.

### Bridge daemon won't terminate

`mcp-clean-state --kill-daemons` uses SIGKILL / `TerminateProcess`. If a
process survives, it likely was not the lock owner — manually kill via
your task manager and re-run the cleanup.

---

## References

- Spec: `~/projects/.superpower/mcp-core/specs/2026-04-30-multi-mode-stdio-http-architecture.md`
- Plan: `~/projects/.superpower/mcp-core/plans/2026-04-30-multi-mode-stdio-http-architecture.md`
- Predecessor migration: `docs/migration-from-mcp-relay-core.md`
