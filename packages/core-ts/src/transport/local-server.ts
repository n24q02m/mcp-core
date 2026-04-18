/**
 * Local MCP server entry point combining OAuth 2.1 AS + Streamable HTTP transport.
 *
 * Composes:
 *  1. OAuth 2.1 AS (credential form + token exchange) -- serves /authorize,
 *     /token, /otp, /setup-status, /.well-known/*
 *  2. MCP Streamable HTTP transport -- serves /mcp with optional Bearer auth
 *  3. /health endpoint -- liveness probe
 *
 * For servers without credential input (e.g. godot) ``relaySchema`` may be
 * omitted: only /mcp (unauthenticated) and /health are served.
 *
 * This is a TypeScript port of ``core-py``'s ``local_server.py``. Route layout,
 * Bearer enforcement, and lifecycle semantics are kept identical.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import type { RelayConfigSchema } from '../auth/credential-form.js'
import {
  createDelegatedOAuthApp,
  type DelegatedOAuthAppOptions,
  type DelegatedOAuthAppResult
} from '../auth/delegated-oauth-app.js'
import {
  type CredentialsCallback,
  createLocalOAuthApp,
  type LocalOAuthAppResult,
  type StepCallback
} from '../auth/local-oauth-app.js'
import { jsonResponse } from '../auth/router.js'
import type { JWTIssuer } from '../oauth/jwt-issuer.js'

export interface RunLocalServerOptions {
  /** Identifier used for JWT iss/aud and credential storage. */
  serverName: string
  /** If undefined, server has NO auth (e.g., godot). */
  relaySchema?: RelayConfigSchema
  /**
   * Mutually exclusive with `relaySchema`. When set, the OAuth app is the
   * delegated provider (upstream redirect or device_code) instead of the local
   * credential form. The `serverName` and `jwtIssuer` are supplied by this
   * function; callers provide only `flow`, `upstream`, and `onTokenReceived`.
   */
  delegatedOAuth?: Omit<DelegatedOAuthAppOptions, 'serverName' | 'jwtIssuer'>
  /** 0 = auto-find a free port. Default: 0. */
  port?: number
  /** Host to bind. Default '127.0.0.1'. */
  host?: string
  /** Optional callback invoked with credentials after POST /authorize. */
  onCredentialsSaved?: CredentialsCallback
  /** Optional callback invoked with step data after POST /otp. */
  onStepSubmitted?: StepCallback
  /**
   * Called with ``markSetupComplete`` function after server ready. Callers use
   * this to wire their credential_state module so background tasks can update
   * the form's status.
   */
  setupCompleteHook?: (markComplete: (key?: string) => void) => void
  /**
   * Optional renderer used in place of the default credential form on GET
   * /authorize. Passed through to ``createLocalOAuthApp``.
   */
  customCredentialFormHtml?: (schema: RelayConfigSchema, options: { submitUrl: string }) => string
}

export interface LocalServerHandle {
  /** Actual TCP port bound. Non-zero even when ``options.port`` was 0. */
  port: number
  /** Host bound. */
  host: string
  /** Cleanly close transport + http server. */
  close: () => Promise<void>
}

/**
 * Start an HTTP server with optional local OAuth AS + MCP Streamable HTTP transport.
 *
 * Behavior:
 *  - If ``relaySchema`` is provided, serves OAuth routes (/authorize, /token,
 *    /otp, /setup-status, /.well-known/*) AND /mcp with Bearer auth.
 *  - If ``relaySchema`` is undefined (e.g., godot), serves ONLY /mcp without
 *    auth (plus /health).
 *  - Binds to ``host:port``. Port 0 auto-assigns via the OS.
 *  - Returns a handle for lifecycle management; the server runs in the
 *    background until ``close()`` is called.
 */
export async function runLocalServer(
  serverFactory: () => McpServer,
  options: RunLocalServerOptions
): Promise<LocalServerHandle> {
  const host = options.host ?? '127.0.0.1'
  const wantedPort = options.port ?? 0

  let oauthApp: LocalOAuthAppResult | DelegatedOAuthAppResult | null = null
  let jwtIssuer: JWTIssuer | null = null

  if (options.relaySchema && options.delegatedOAuth) {
    throw new Error('`relaySchema` and `delegatedOAuth` are mutually exclusive')
  }

  if (options.delegatedOAuth) {
    oauthApp = await createDelegatedOAuthApp({
      serverName: options.serverName,
      flow: options.delegatedOAuth.flow,
      upstream: options.delegatedOAuth.upstream,
      onTokenReceived: options.delegatedOAuth.onTokenReceived
    })
    jwtIssuer = oauthApp.jwtIssuer
  } else if (options.relaySchema) {
    oauthApp = await createLocalOAuthApp({
      serverName: options.serverName,
      relaySchema: options.relaySchema,
      onCredentialsSaved: options.onCredentialsSaved,
      onStepSubmitted: options.onStepSubmitted,
      customCredentialFormHtml: options.customCredentialFormHtml
    })
    jwtIssuer = oauthApp.jwtIssuer
  }

  // MCP server + transport. Stateless mode (sessionIdGenerator undefined) to
  // match the Python StreamableHTTPSessionManager default.
  const mcpServer = serverFactory()
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined })
  await mcpServer.connect(transport)

  async function mcpHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Bearer auth if configured.
    if (jwtIssuer) {
      const authHeader = req.headers.authorization
      const match = authHeader?.match(/^Bearer\s+(\S.*)$/i)
      const token = match?.[1]?.trim()
      if (!token) {
        res.writeHead(401, { 'WWW-Authenticate': 'Bearer' })
        res.end()
        return
      }
      try {
        await jwtIssuer.verifyAccessToken(token)
      } catch {
        res.writeHead(401, { 'WWW-Authenticate': 'Bearer error="invalid_token"' })
        res.end()
        return
      }
    }
    // Delegate to MCP transport.
    await transport.handleRequest(req, res)
  }

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const pathname = url.pathname

    // Route /mcp to MCP transport (with optional Bearer auth).
    if (pathname === '/mcp') {
      await mcpHandler(req, res)
      return
    }

    // Liveness probe. Always available.
    if (pathname === '/health') {
      jsonResponse(res, 200, { status: 'ok', server: options.serverName })
      return
    }

    // Route everything else to OAuth app if present.
    if (oauthApp) {
      await oauthApp.handler(req, res)
      return
    }

    // No OAuth app and no match -- 404.
    jsonResponse(res, 404, { error: 'not_found' })
  }

  const httpServer: Server = createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'internal_error' }))
      }
    })
  })

  await new Promise<void>((resolve, reject) => {
    httpServer.once('error', reject)
    httpServer.listen(wantedPort, host, () => {
      httpServer.removeListener('error', reject)
      resolve()
    })
  })

  const addr = httpServer.address() as AddressInfo
  const actualPort = addr.port

  // Invoke setup hook with markSetupComplete so caller can wire background
  // tasks (e.g., GDrive token poll) to update the form status.
  if (options.setupCompleteHook && oauthApp) {
    options.setupCompleteHook(oauthApp.markSetupComplete)
  }

  return {
    port: actualPort,
    host,
    close: () =>
      new Promise<void>((resolve, reject) => {
        const delegatedShutdown = oauthApp && 'shutdown' in oauthApp ? oauthApp.shutdown() : Promise.resolve()
        delegatedShutdown
          .then(() => transport.close())
          .then(() => {
            httpServer.close((err) => (err ? reject(err) : resolve()))
          })
          .catch(reject)
      })
  }
}
