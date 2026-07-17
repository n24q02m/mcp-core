/**
 * Unified single-user credential store router.
 *
 * Single-user MCP credentials historically lived in the shared, machine-bound
 * `config.enc` (`storage/config-file.ts`), keyed by the console name. But the
 * CLI built-ins (`buildCli` config/doctor) and the whole Python stack read and
 * write via `PerPluginStore`, keyed by the plugin slug -- so the two never saw
 * each other's data: a TS server would save credentials the CLI then reported
 * as "not configured".
 *
 * This module unifies single-user storage onto `PerPluginStore` (matching the
 * wet-mcp Python `credential_state.py` cutover) while keeping a READ fallback
 * to the legacy `config.enc`, so credentials already on disk keep working with
 * ZERO re-auth. On the next WRITE the credentials migrate to the per-plugin
 * store; DELETE clears BOTH stores.
 *
 *   WRITE  -> PerPluginStore(pluginName).save(config)
 *   READ   -> PerPluginStore(pluginName).load() ?? legacy readConfig(serverName)
 *   DELETE -> PerPluginStore(pluginName).clear() + legacy deleteConfig(serverName)
 *
 * `pluginName` defaults to `serverName` with a trailing `-mcp` stripped -- the
 * same convention `buildCli` and core-py `build_cli` use -- so single-user
 * credentials land under the SAME slug the CLI reads and the multi-user
 * per-sub store keys on (`better-email`, `better-notion`, `wet`, ...). Pass it
 * explicitly when the slug differs from that default (telegram saves under
 * `"telegram"` though its console name is `"better-telegram-mcp"`).
 *
 * Multi-user HTTP storage (per-JWT-sub) is unaffected: it uses
 * `PerPluginStore(pluginName, sub)`, a distinct on-disk key from the
 * single-user `PerPluginStore(pluginName)` this module manages.
 */

import {
  deleteConfig as deleteLegacyConfig,
  readConfig as readLegacyConfig,
  SETUP_COMPLETE_KEY
} from './config-file.js'
import { PerPluginStore } from './per-plugin-store.js'

/**
 * Derive the credential-storage plugin slug from a console/server name by
 * stripping a trailing `-mcp`. Shared with `buildCli` so the CLI reads exactly
 * the slug single-user writes land under.
 */
export function pluginNameForServer(serverName: string): string {
  return serverName.replace(/-mcp$/, '')
}

/**
 * Read a server's single-user credential config.
 *
 * Prefers the per-plugin store; falls back to the legacy shared `config.enc`
 * so credentials written by the pre-unification path stay readable with no
 * re-auth. Returns `null` when neither store has an entry.
 */
export async function readStoredConfig(
  serverName: string,
  pluginName: string = pluginNameForServer(serverName)
): Promise<Record<string, string> | null> {
  const fromStore = await new PerPluginStore(pluginName).load()
  // Single-user blobs are always string maps (written by writeStoredConfig /
  // markSetupComplete below); the cast restates that invariant.
  if (fromStore !== null) return fromStore as Record<string, string>
  return readLegacyConfig(serverName)
}

/**
 * Write a server's single-user credential config to the per-plugin store.
 *
 * Full replace, mirroring the legacy `writeConfig` contract and the wet-mcp
 * Python `save()` call: callers that need to preserve prior keys read first and
 * merge (see `markSetupComplete`). The write also serves as the migration
 * trigger -- an existing legacy `config.enc` entry is superseded because
 * `readStoredConfig` prefers the per-plugin store from here on.
 */
export async function writeStoredConfig(
  serverName: string,
  config: Record<string, string>,
  pluginName: string = pluginNameForServer(serverName)
): Promise<void> {
  await new PerPluginStore(pluginName).save(config)
}

/**
 * Delete a server's single-user credential config from BOTH stores.
 *
 * Clears the per-plugin store and the legacy `config.enc` entry so a reset
 * leaves nothing behind in either backend.
 */
export async function deleteStoredConfig(
  serverName: string,
  pluginName: string = pluginNameForServer(serverName)
): Promise<void> {
  await new PerPluginStore(pluginName).clear()
  await deleteLegacyConfig(serverName)
}

/**
 * Set the persistent `_setup_complete` flag in a server's single-user config,
 * preserving any existing keys. Reads through the unified path (so a legacy
 * entry is migrated forward) and writes the merged result to the per-plugin
 * store. Creates an entry with just the flag when nothing exists (useful for
 * all-optional schemas where the user may submit an empty form).
 */
export async function markSetupComplete(
  serverName: string,
  pluginName: string = pluginNameForServer(serverName)
): Promise<void> {
  const existing = (await readStoredConfig(serverName, pluginName)) ?? {}
  existing[SETUP_COMPLETE_KEY] = 'true'
  await writeStoredConfig(serverName, existing, pluginName)
}
