/**
 * Helper to register `config__open_relay` MCP tool — HTTP-only mode.
 *
 * After the stdio-pure + http-multi-user split, the relay config form is
 * served by the HTTP server itself at ``<PUBLIC_URL>/authorize``. The
 * ``config__open_relay`` tool directs the user to that URL.
 *
 * When the connected client declares URL-mode elicitation
 * (``capabilities.elicitation.url``, SEP-1036), the tool asks the client to
 * present a consent prompt and open the URL via ``Server.elicitInput`` so the
 * credential form is opened out-of-band without the LLM in the loop. Clients
 * that do NOT declare the capability fall back to the legacy behaviour: the
 * tool returns the URL and best-effort opens the user's default browser
 * server-side. There is no daemon-bridge discovery, no respawn, and no
 * session deduplication — the HTTP server's own session tracking handles
 * concurrent setup attempts.
 *
 * In stdio mode, the relay form does not exist; the tool returns
 * ``stdio_unsupported`` so plugin code can render a "switch to HTTP mode"
 * message instead of misleading the user with an unreachable URL.
 */

import { randomUUID } from 'node:crypto'
import type { ClientCapabilities, ElicitRequestURLParams, ElicitResult } from '@modelcontextprotocol/sdk/types.js'
import { tryOpenBrowser } from './browser.js'

export interface OpenRelayResult {
  url: string
  browserOpened: boolean
  status: 'configured' | 'unconfigured' | 'expired' | 'session_active' | 'stdio_unsupported'
  elicitation?: 'accepted' | 'declined' | 'cancelled'
}

/**
 * Minimal surface required to drive URL-mode elicitation. Satisfied by the
 * low-level `Server` from `@modelcontextprotocol/sdk` (`mcp.server`), which
 * exposes both `getClientCapabilities` and `elicitInput`.
 */
export interface ElicitationServer {
  getClientCapabilities: () => ClientCapabilities | undefined
  elicitInput: (params: ElicitRequestURLParams) => Promise<ElicitResult>
}

export interface OpenRelayHandlerOptions {
  serverName: string
  publicUrl: string | null
  elicitation?: ElicitationServer
}

// Maps the client's ElicitResult.action to the tool's outcome field.
const ELICIT_ACTION_MAP: Record<string, 'accepted' | 'declined' | 'cancelled'> = {
  accept: 'accepted',
  decline: 'declined',
  cancel: 'cancelled'
}

function clientSupportsUrlElicitation(server: ElicitationServer): boolean {
  return server.getClientCapabilities()?.elicitation?.url != null
}

/**
 * Build the `open_relay` handler closure. Tests can call
 * ``buildOpenRelayHandler({ serverName, publicUrl })`` directly without
 * needing a real MCP server instance.
 *
 * When `elicitation` is supplied AND the client declared URL-mode
 * elicitation, the handler drives `elicitInput` and returns the accept /
 * decline / cancel outcome. Otherwise it returns the legacy dict
 * (`{ url, browserOpened, status }`) unchanged.
 */
export function buildOpenRelayHandler(options: OpenRelayHandlerOptions): () => Promise<OpenRelayResult> {
  return async function openRelay(): Promise<OpenRelayResult> {
    if (!options.publicUrl) {
      return { url: '', browserOpened: false, status: 'stdio_unsupported' }
    }
    const url = `${options.publicUrl.replace(/\/$/, '')}/authorize`
    const { elicitation } = options
    if (elicitation && clientSupportsUrlElicitation(elicitation)) {
      const message = `Open the ${options.serverName} configuration page to enter your credentials securely in your browser.`
      const result = await elicitation.elicitInput({
        mode: 'url',
        message,
        url,
        elicitationId: randomUUID()
      })
      return {
        url,
        browserOpened: false,
        status: 'unconfigured',
        elicitation: ELICIT_ACTION_MAP[result.action] ?? 'accepted'
      }
    }
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
 * registerOpenRelayTool(mcp, SERVER_NAME, PUBLIC_URL, mcp.server)
 * ```
 *
 * Pass ``null`` for ``publicUrl`` when the server is running in stdio mode;
 * the tool will return ``status: 'stdio_unsupported'`` so the caller can
 * surface a clear "switch to HTTP mode" message.
 *
 * Pass the low-level `Server` (`mcp.server`) as ``elicitation`` to enable
 * URL-mode elicitation for capable clients. When omitted, the tool keeps
 * the legacy browser-open behaviour for every client.
 */
export function registerOpenRelayTool(
  mcp: ToolRegistrar,
  serverName: string,
  publicUrl: string | null,
  elicitation?: ElicitationServer
): void {
  const handler = buildOpenRelayHandler({ serverName, publicUrl, elicitation })
  mcp.tool(
    {
      name: 'config__open_relay',
      // Deliberately conditional. The handler returns `browserOpened: false`
      // whenever no browser could be launched (headless, CI, the env-guard, no
      // desktop session), and this text is read by a model that then speaks for
      // the tool. "Open the ... form in the user's browser" reads as a
      // guarantee, so a model can report "opened it in your browser" while the
      // result says otherwise -- the user is then waiting on a tab that will
      // never appear. The URL is what the tool always delivers; the browser is
      // a convenience on top, and the wording says so in that order.
      description: `Get the relay configuration URL for ${serverName}, opening it in the user's browser when possible.`
    },
    handler
  )
}
