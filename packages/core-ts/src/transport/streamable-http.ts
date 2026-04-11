/**
 * Streamable HTTP 2025-11-25 transport wrapper for mcp-core TypeScript.
 *
 * Thin convenience wrapper around `@modelcontextprotocol/sdk`'s
 * `StreamableHTTPServerTransport` that pairs it with an `McpServer`
 * instance and an optional OAuth Bearer validation middleware.
 *
 * The SDK already implements the full 2025-11-25 transport spec
 * (session management, SSE streaming, stateful / stateless modes),
 * so this wrapper focuses on the mcp-core ergonomics:
 *
 *  - one-call `connect()` that wires server <-> transport
 *  - `handleRequest(req, res)` that applies the OAuth middleware
 *    first and short-circuits with 401 on missing / invalid token
 *  - explicit `host` / `port` properties for lifecycle management
 *    (the actual port bind is left to the caller's http.Server)
 */

import type { IncomingMessage, ServerResponse } from 'node:http'

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
  StreamableHTTPServerTransport,
  type StreamableHTTPServerTransportOptions
} from '@modelcontextprotocol/sdk/server/streamableHttp.js'

import type { OAuthMiddleware } from './oauth-middleware.js'

export interface StreamableHTTPServerOptions {
  /** MCP server instance that handles requests */
  server: McpServer
  /** Host to advertise (used for logging / display only) */
  host?: string
  /** Port to advertise (used for logging / display only) */
  port: number
  /** Optional OAuth middleware for Bearer token validation */
  oauthMiddleware?: OAuthMiddleware
  /** Transport options forwarded to StreamableHTTPServerTransport */
  transportOptions?: StreamableHTTPServerTransportOptions
}

export class StreamableHTTPServer {
  readonly host: string
  readonly port: number
  private readonly _server: McpServer
  private readonly _oauth?: OAuthMiddleware
  private readonly _transport: StreamableHTTPServerTransport
  private _connected = false

  constructor(options: StreamableHTTPServerOptions) {
    this._server = options.server
    this.host = options.host ?? '127.0.0.1'
    this.port = options.port
    this._oauth = options.oauthMiddleware
    this._transport = new StreamableHTTPServerTransport(options.transportOptions ?? { sessionIdGenerator: undefined })
  }

  /** Connect the MCP server to the transport. Call once before handleRequest. */
  async connect(): Promise<void> {
    if (this._connected) return
    await this._server.connect(this._transport)
    this._connected = true
  }

  /**
   * Handle an incoming HTTP request. Applies OAuth validation first if
   * configured, then delegates to the SDK transport.
   */
  async handleRequest(req: IncomingMessage, res: ServerResponse, parsedBody?: unknown): Promise<void> {
    if (this._oauth) {
      const allowed = await this._oauth.validate(req, res)
      if (!allowed) return
    }
    await this._transport.handleRequest(req, res, parsedBody)
  }

  /** Expose the underlying transport for advanced use cases. */
  get transport(): StreamableHTTPServerTransport {
    return this._transport
  }

  /** Close the transport and drain any active sessions. */
  async close(): Promise<void> {
    await this._transport.close()
    this._connected = false
  }
}
