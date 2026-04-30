# Shared Embedding Daemon (opt-in)

`docker-compose.yml` in this directory runs the shared
`mcp-embedding-daemon` as a long-lived local container. It is **opt-in**
— each plugin works standalone without it (each loads its own embedding
model in-process). The shared daemon exists for power users running
multiple plugins that benefit from a single model load + warm cache.

---

## Purpose

Three plugins use embeddings for semantic search / retrieval:

- **wet-mcp** — embeds web search snippets and Google Drive document chunks.
- **mnemo-mcp** — embeds memory entries for similarity recall.
- **better-code-review-graph** — embeds code symbols + commit messages.

Without the shared daemon, each plugin loads its own copy of the embedding
model into RAM (≈400-800 MB depending on the model). On a workstation
running all three plugins simultaneously, that's 1.2-2.4 GB duplicated
across three Python processes.

With the shared daemon, the model is loaded **once** in a single
container. Each plugin makes a local HTTP call to `localhost:8001` to
embed text — adding ~1-3 ms per embedding (negligible for the typical
batch size).

---

## When to use

Enable the shared daemon if **any** of these apply:

- You run wet + mnemo + crg concurrently and want lower RAM usage.
- Your machine has < 16 GB RAM and you want headroom for IDE / browser.
- You want the embedding model warm across plugin restarts (faster cold
  start when Claude Code re-spawns a plugin).

Skip the shared daemon if:

- You only run one of the three plugins.
- You have plenty of RAM (≥ 32 GB) and prefer fewer moving parts.
- You cannot run Docker on your machine.

---

## Setup

### 1. Start the daemon

```bash
cd ~/projects/mcp-core/docs/shared-services
docker compose up -d
```

Verify it's running:

```bash
docker compose ps
curl http://localhost:8001/health
```

Expected: `{"status": "ok"}` (or similar — see daemon README).

### 2. Configure plugins

Set the environment variable `EMBEDDING_DAEMON_URL=http://localhost:8001`
in each plugin's manifest:

```json
{
  "mcpServers": {
    "wet": {
      "command": "uvx",
      "args": ["--python", "3.13", "wet-mcp"],
      "env": {
        "MCP_TRANSPORT": "stdio",
        "EMBEDDING_DAEMON_URL": "http://localhost:8001"
      }
    },
    "mnemo": {
      "command": "uvx",
      "args": ["--python", "3.13", "mnemo-mcp"],
      "env": {
        "MCP_TRANSPORT": "stdio",
        "EMBEDDING_DAEMON_URL": "http://localhost:8001"
      }
    },
    "better-code-review-graph": {
      "command": "uvx",
      "args": ["--python", "3.13", "better-code-review-graph"],
      "env": {
        "MCP_TRANSPORT": "stdio",
        "EMBEDDING_DAEMON_URL": "http://localhost:8001"
      }
    }
  }
}
```

When `EMBEDDING_DAEMON_URL` is set, the plugin skips the in-process
model load and calls the daemon for every embedding request. When
unset, the plugin falls back to in-process embedding (default).

### 3. Restart your MCP client

Restart Claude Code (or Cursor / VS Code Copilot / etc.) so the
plugins pick up the new `EMBEDDING_DAEMON_URL` env var.

---

## Operations

### Stop the daemon

```bash
cd ~/projects/mcp-core/docs/shared-services
docker compose down
```

Plugins fall back to in-process embedding on the next request.

### Update the daemon

```bash
cd ~/projects/mcp-core/docs/shared-services
docker compose pull
docker compose up -d
```

### View logs

```bash
docker compose logs -f embedding-daemon
```

### Cache location

The embedding model + warm cache live in the named volume
`embedding-cache`. Inspect it:

```bash
docker volume inspect shared-services_embedding-cache
```

To wipe it (forces re-download on next start):

```bash
docker compose down -v
```

---

## Network notes

The daemon binds to `127.0.0.1:8001` only — it is **not exposed** to the
LAN. If you need a remote shared daemon (multiple workstations sharing
a single GPU machine), edit the `ports:` line to bind on `0.0.0.0:8001`
and set `EMBEDDING_DAEMON_URL=http://<gpu-host>:8001` in plugin manifests.
This is uncommon — most users run the daemon locally.

---

## References

- `mcp-core/packages/embedding-daemon/` — source for the daemon itself.
- Migration doc: `~/projects/mcp-core/docs/migration-2026-04-30.md` —
  context for the multi-mode architecture this slot-fits into.
