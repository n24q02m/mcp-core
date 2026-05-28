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

import { randomUUID } from 'node:crypto'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import type { JWTPayload } from 'jose'
import type { RelayConfigSchema } from '../auth/credential-form.js'
import { isSchemaComplete } from '../auth/credential-form.js'
import { createDelegatedOAuthApp, type DelegatedOAuthAppResult, type FlowType } from '../auth/delegated-oauth-app.js'
import {
  type CredentialsCallback,
  createLocalOAuthApp,
  type LocalOAuthAppResult,
  type StepCallback
} from '../auth/local-oauth-app.js'
import { jsonResponse } from '../auth/router.js'
import { LifecycleLock, refreshLockTimestamp, sweepStaleLocks } from '../lifecycle/lock.js'
import type { JWTIssuer } from '../oauth/jwt-issuer.js'
import { tryOpenBrowser } from '../relay/browser.js'
import { readConfig } from '../storage/config-file.js'

/** Decoded JWT claims returned by JWTIssuer.verifyAccessToken. */
export type JWTClaims = JWTPayload

export interface RunHttpServerOptions {
  /** Identifier used for JWT iss/aud and credential storage. */
  serverName: string
  /** If undefined, server has NO auth (e.g., godot). */
  relaySchema?: RelayConfigSchema
  /** MCP server instance factory. */
  serverFactory: () => McpServer
  /** Initial port to attempt. 0 means auto-find. */
  port?: number
  /** Host to bind. Defaults to 127.0.0.1. */
  host?: string
  /** Callback invoked when the user submits creds via form. */
  onCredentialsSaved?: CredentialsCallback
  /** Callback for multi-step credential input (OTP / 2FA). */
  onStepSubmitted?: StepCallback
  /** Optional setup hook. */
  setupCompleteHook?: (markComplete: (key?: string) => void, markFailed: (key?: string, error?: string) => void) => void
  /** Optional form renderer override. */
  customCredentialFormHtml?: (
    schema: RelayConfigSchema,
    options: {
      submitUrl: string
      prefill?: Record<string, string>
    }
  ) => string
  /** Optional delegated OAuth config. */
  delegatedOAuth?: {
    flow: FlowType
    upstream: {
      tokenUrl: string
      clientId: string
      clientSecret?: string
      scopes?: string[]
      authorizeUrl?: string
      callbackPath?: string
      deviceAuthUrl?: string
      pollIntervalMs?: number
    }
    onTokenReceived: (tokens: Record<string, unknown>) => string | undefined | Promise<string | undefined>
  }
  /** Bearer auth bypass for external auth boundary. */
  authDisabled?: boolean
  /** Optional middleware after JWT verification. */
  authScope?: (claims: JWTClaims, next: () => Promise<void>) => Promise<void>
}

export interface HttpServerHandle {
  port: number
  host: string
  close: () => Promise<void>
}

/**
 * Start a local OAuth + MCP server and return a handle.
 */
export async function runHttpServer(options: RunHttpServerOptions): Promise<HttpServerHandle> {
  const { serverFactory, serverName, port: wantedPort = 0, host = '127.0.0.1' } = options

  let oauthApp: LocalOAuthAppResult | DelegatedOAuthAppResult | undefined
  let jwtIssuer: JWTIssuer | undefined

  if (options.relaySchema && options.delegatedOAuth) {
    throw new Error('`relaySchema` and `delegatedOAuth` are mutually exclusive')
  }

  if (options.delegatedOAuth) {
    oauthApp = await createDelegatedOAuthApp({
      serverName,
      flow: options.delegatedOAuth.flow,
      upstream: options.delegatedOAuth.upstream as any,
      onTokenReceived: options.delegatedOAuth.onTokenReceived
    })
    jwtIssuer = oauthApp.jwtIssuer
  } else if (options.relaySchema) {
    oauthApp = await createLocalOAuthApp({
      serverName,
      relaySchema: options.relaySchema,
      onCredentialsSaved: options.onCredentialsSaved,
      onStepSubmitted: options.onStepSubmitted,
      customCredentialFormHtml: options.customCredentialFormHtml as any
    })
    jwtIssuer = oauthApp.jwtIssuer
  }

  const transports = new Map<string, StreamableHTTPServerTransport>()
  const servers = new Map<string, McpServer>()

  async function handleSessionRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const sessionHeader = req.headers['mcp-session-id']
    const incomingSessionId = Array.isArray(sessionHeader) ? sessionHeader[0] : sessionHeader

    let transport = incomingSessionId ? transports.get(incomingSessionId) : undefined

    if (!transport) {
      const server = serverFactory()
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sessionId) => {
          if (transport) transports.set(sessionId, transport)
          servers.set(sessionId, server)
        },
        onsessionclosed: (sessionId) => {
          transports.delete(sessionId)
          servers.delete(sessionId)
          server.close().catch(() => {
            /* best-effort cleanup */
          })
        }
      })
      await server.connect(transport)
    }

    await transport.handleRequest(req, res)
  }

  async function mcpHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (jwtIssuer && options.authDisabled) {
      const anonymousClaims = { sub: 'anonymous', anonymous: true } as unknown as JWTClaims
      if (options.authScope) {
        await options.authScope(anonymousClaims, async () => {
          await handleSessionRequest(req, res)
        })
        return
      }
      await handleSessionRequest(req, res)
      return
    }
    if (jwtIssuer) {
      const authHeader = req.headers.authorization
      const match = authHeader?.match(/^Bearer\s+(\S.*)$/i)
      const token = match?.[1]?.trim()
      if (!token) {
        res.writeHead(401, { 'WWW-Authenticate': 'Bearer' })
        res.end()
        return
      }
      let claims: JWTClaims
      try {
        claims = await jwtIssuer.verifyAccessToken(token)
      } catch {
        res.writeHead(401, { 'WWW-Authenticate': 'Bearer error="invalid_token"' })
        res.end()
        return
      }
      if (options.authScope) {
        await options.authScope(claims, async () => {
          await handleSessionRequest(req, res)
        })
        return
      }
    }
    await handleSessionRequest(req, res)
  }

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const pathname = url.pathname

    if (pathname === '/mcp') {
      await mcpHandler(req, res)
      return
    }

    if (pathname === '/health') {
      jsonResponse(res, 200, { status: 'ok', server: serverName })
      return
    }

    if (oauthApp) {
      await oauthApp.handler(req, res)
      return
    }

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

  const swept = sweepStaleLocks(serverName)
  if (swept > 0) {
    console.error(`[runHttpServer] cleaned ${swept} stale lock(s) for ${serverName}`)
  }

  const proxyToken = jwtIssuer ? await jwtIssuer.issueAccessToken('proxy', 31536000) : ''
  const lock = new LifecycleLock(serverName, actualPort, proxyToken)
  lock.acquire()
  const lockFile = lock.path

  const lockRefreshInterval = setInterval(() => refreshLockTimestamp(lockFile), 3600 * 1000)
  if (typeof lockRefreshInterval.unref === 'function') {
    lockRefreshInterval.unref()
  }

  if (oauthApp) {
    try {
      const existingConfig = await readConfig(serverName)
      const configComplete = options.relaySchema
        ? isSchemaComplete(existingConfig, options.relaySchema)
        : existingConfig !== null

      if (!configComplete && process.env.NODE_ENV !== 'test') {
        const setupUrl = `http://${host}:${actualPort}/`
        await tryOpenBrowser(setupUrl)
      }
    } catch {
      /* best-effort: never crash startup on browser-open failure */
    }
  }

  if (options.setupCompleteHook && oauthApp) {
    const markSetupFailed =
      'markSetupFailed' in oauthApp && typeof oauthApp.markSetupFailed === 'function'
        ? oauthApp.markSetupFailed
        : undefined
    if (options.setupCompleteHook.length >= 2 && markSetupFailed !== undefined) {
      ;(options.setupCompleteHook as (mc: (key?: string) => void, mf: (key?: string, error?: string) => void) => void)(
        oauthApp.markSetupComplete,
        markSetupFailed
      )
    } else {
      ;(options.setupCompleteHook as (mc: (key?: string) => void) => void)(oauthApp.markSetupComplete)
    }
  }

  return {
    port: actualPort,
    host,
    close: async () => {
      if (oauthApp && 'shutdown' in oauthApp) {
        await oauthApp.shutdown()
      }

      for (const transport of transports.values()) {
        try {
          await transport.close()
        } catch {
          /* best-effort cleanup */
        }
      }
      for (const server of servers.values()) {
        try {
          await server.close()
        } catch {
          /* best-effort cleanup */
        }
      }
      transports.clear()
      servers.clear()

      if (lockRefreshInterval !== null) {
        clearInterval(lockRefreshInterval)
      }

      return new Promise<void>((resolve, reject) => {
        httpServer.close(async (err) => {
          if (lock) {
            lock.release()
          }
          if (err) {
            reject(err)
          } else {
            resolve()
          }
        })
      })
    }
  }
}
