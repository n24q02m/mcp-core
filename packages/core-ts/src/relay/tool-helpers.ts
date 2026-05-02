/**
 * Helper to register `config__open_relay` MCP tool — HTTP-only mode.
 *
 * After the stdio-pure + http-multi-user split, the relay config form is
 * served by the HTTP server itself at ``<PUBLIC_URL>/authorize``. The
 * ``config__open_relay`` tool simply returns that URL and best-effort opens
 * the user's default browser. There is no daemon-bridge discovery, no
 * respawn, and no session deduplication — the HTTP server's own session
 * tracking handles concurrent setup attempts.
 *
 * In stdio mode, the relay form does not exist; the tool returns
 * ``stdio_unsupported`` so plugin code can render a "switch to HTTP mode"
 * message instead of misleading the user with an unreachable URL.
 */

import { tryOpenBrowser } from './browser.js'

export interface OpenRelayResult {
  url: string
  browserOpened: boolean
  status: 'configured' | 'unconfigured' | 'expired' | 'session_active' | 'stdio_unsupported'
}

export interface OpenRelayHandlerOptions {
  serverName: string
  publicUrl: string | null
}

/**
 * Build the `open_relay` handler closure. Tests can call
 * ``buildOpenRelayHandler({ serverName, publicUrl })`` directly without
 * needing a real MCP server instance.
 */
export function buildOpenRelayHandler(options: OpenRelayHandlerOptions): () => Promise<OpenRelayResult> {
  return async function openRelay(): Promise<OpenRelayResult> {
    if (!options.publicUrl) {
      return { url: '', browserOpened: false, status: 'stdio_unsupported' }
    }
    const url = `${options.publicUrl.replace(/\/$/, '')}/authorize`
    const opened = await tryOpenBrowser(url)
    return { url, browserOpened: !!opened, status: 'unconfigured' }
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
 * registerOpenRelayTool(mcp, SERVER_NAME, PUBLIC_URL)
 * ```
 *
 * Pass ``null`` for ``publicUrl`` when the server is running in stdio mode;
 * the tool will return ``status: 'stdio_unsupported'`` so the caller can
 * surface a clear "switch to HTTP mode" message.
 */
export function registerOpenRelayTool(mcp: ToolRegistrar, serverName: string, publicUrl: string | null): void {
  const handler = buildOpenRelayHandler({ serverName, publicUrl })
  mcp.tool(
    {
      name: 'config__open_relay',
      description: `Open the relay configuration form for ${serverName} in the user's browser.`
    },
    handler
  )
}
