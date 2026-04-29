/**
 * Helper to register `config__open_relay` MCP tool — D6 (Task 1.8).
 *
 * Each consumer server calls `registerOpenRelayTool(mcp, SERVER_NAME, SCHEMA)`
 * to get the standard tool registered into its MCP server instance. The tool,
 * when invoked by the LLM, returns the relay form URL and attempts to open
 * the user's browser. If the daemon is dead it auto-respawns; if a relay
 * session is already active in another Claude Code window, the handler
 * returns `session_active` status without auto-opening a second browser tab.
 */

import { daemonCredState, daemonIsAlive, daemonRelayUrl, daemonRespawn } from '../transport/smart-stdio.js'
import { tryOpenBrowser } from './browser.js'
import { isSessionActive } from './session.js'

export interface OpenRelayResult {
  url: string
  browserOpened: boolean
  status: 'configured' | 'unconfigured' | 'expired' | 'session_active'
}

export interface OpenRelaySchema {
  server: string
  fields: Array<{
    name: string
    label?: string
    required?: boolean
    secret?: boolean
    [key: string]: unknown
  }>
  [key: string]: unknown
}

/**
 * Per-server session probe.
 *
 * The current session module tracks one global active form session at a
 * time (Task 1.5), so the server name is currently ignored. Kept as a
 * one-arg helper to give vi.spyOn hooks a single, server-aware seam that
 * future per-server session tracking can implement without refactoring
 * callers.
 */
function isSessionActiveForServer(_serverName: string): boolean {
  return isSessionActive()
}

/**
 * Build the `open_relay` handler closure. Separated out for testability —
 * tests can call `buildOpenRelayHandler('demo', SCHEMA)` directly without
 * needing a real MCP server instance.
 */
export function buildOpenRelayHandler(
  serverName: string,
  _schema: OpenRelaySchema | unknown
): () => Promise<OpenRelayResult> {
  return async function openRelay(): Promise<OpenRelayResult> {
    const url = daemonIsAlive(serverName) ? daemonRelayUrl(serverName) : daemonRespawn(serverName)
    const credState = daemonCredState(serverName) as OpenRelayResult['status']

    if (isSessionActiveForServer(serverName)) {
      return { url, browserOpened: false, status: 'session_active' }
    }

    const opened = await tryOpenBrowser(url)
    return { url, browserOpened: !!opened, status: credState }
  }
}

/**
 * Minimal shape we require from the MCP server instance to register the
 * tool. Both `@modelcontextprotocol/sdk`'s `McpServer.tool` and the
 * FastMCP-style helpers used in consumer servers conform to this surface.
 */
export interface ToolRegistrar {
  tool: (config: { name: string; description?: string }, handler: () => Promise<OpenRelayResult>) => void
}

/**
 * Register `config__open_relay` on the given MCP server instance.
 *
 * Consumer servers add this single line in their tool registry after the
 * other `config__*` registrations:
 *
 * ```ts
 * import { registerOpenRelayTool } from '@n24q02m/mcp-core'
 * registerOpenRelayTool(mcp, SERVER_NAME, RELAY_SCHEMA)
 * ```
 */
export function registerOpenRelayTool(mcp: ToolRegistrar, serverName: string, schema: OpenRelaySchema | unknown): void {
  const handler = buildOpenRelayHandler(serverName, schema)
  mcp.tool(
    {
      name: 'config__open_relay',
      description: `Open the relay configuration form for ${serverName} in the user's browser.`
    },
    handler
  )
}
