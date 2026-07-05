/**
 * Delegated OAuth 2.1 Authorization Server as an HTTP request handler.
 *
 * Unified abstraction for upstream OAuth providers. Fronts two upstream
 * flows behind a single local OAuth 2.1 PKCE facade for the MCP client:
 *
 * - ``redirect`` flow -- classic authorization_code redirect (Notion,
 *   Grafana, GitHub, ...). The local server proxies ``/authorize`` to the
 *   upstream authorize endpoint, handles the callback, exchanges the
 *   upstream code for upstream tokens via ``upstream.tokenUrl``, forwards
 *   the tokens to the consumer via ``onTokenReceived``, then finishes the
 *   local PKCE exchange so the MCP client receives a local JWT.
 * - ``device_code`` flow (RFC 8628) -- used by GDrive, Outlook, etc. The
 *   local server initiates the upstream device authorization, renders a
 *   page showing ``user_code`` + ``verification_url``, runs a background
 *   polling task on ``upstream.tokenUrl`` until the upstream grants a
 *   token, invokes ``onTokenReceived``, and signals completion via the
 *   setup-status endpoint.
 *
 * This is a TypeScript port of core-py's ``delegated_oauth_app.py``.
 * Behavior, protocol, and TTL constants are kept identical for parity.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { JWTIssuer } from '../oauth/jwt-issuer.js'
import { configureRelayLogin, createRelayLoginMiddleware, loginGetHandler, loginPostHandler } from './relay-login.js'
import {
  createRouter,
  htmlResponse,
  jsonResponse,
  parseFormBody,
  parseJsonBody,
  type RequestHandler
} from './router.js'
import { createSessionStore, type SessionKv } from './session-store.js'
import { authorizationServerMetadata, protectedResourceMetadata } from './well-known.js'

export type FlowType = 'device_code' | 'redirect'

export type TokenEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post'

export interface UpstreamOAuthConfig {
  // Common
  tokenUrl: string
  clientId: string
  clientSecret?: string
  scopes?: string[]
  /**
   * How to pass client credentials to the upstream token endpoint.
   * Defaults to ``client_secret_basic`` per RFC 6749 §2.3.1 which mandates
   * basic-auth support. Notion, GitHub, Microsoft identity platform all
   * require basic; Google and Slack accept both.
   */
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod
  // Redirect flow only
  authorizeUrl?: string
  callbackPath?: string
  // Device code flow only
  deviceAuthUrl?: string
  pollIntervalMs?: number
}

export type OAuthTokens = Record<string, unknown>

/**
 * Called after upstream token exchange completes. Return the subject
 * identifier (e.g. provider user id) to use as JWT `sub` in the bearer
 * token issued to the MCP client. Returning `void` / `undefined` falls
 * back to `'local-user'` (single-user mode).
 */
export type TokenCallback = (tokens: OAuthTokens) => string | undefined | void | Promise<string | undefined | void>

export interface DelegatedOAuthAppOptions {
  serverName: string
  flow: FlowType
  upstream: UpstreamOAuthConfig
  onTokenReceived: TokenCallback
  jwtIssuer?: JWTIssuer
  /**
   * Optional durable KV for the delegated-flow handshake state (pending
   * sessions + issued auth codes). Inject in serverless/container deploys so
   * the state survives a cold-start/restart between /authorize and /callback;
   * omit for stdio/single-process (falls back to an in-process map).
   *
   * The caller (not this module) owns constructing this -- typically
   * ``wrapKvBackendAsSessionKv(backendFromEnv(), '<app-kv-namespace>:')``. This
   * module cannot safely guess an app-scoped KV key prefix: a CF Container's
   * ``kv.internal`` outbound handler commonly allowlists keys by app-specific
   * prefix, so an auto-detected generic prefix would be silently rejected
   * (403) by that allowlist. See ``wrapKvBackendAsSessionKv`` in
   * ``session-store.ts``.
   */
  sessionKv?: SessionKv
}

export interface DelegatedOAuthAppResult {
  handler: RequestHandler
  jwtIssuer: JWTIssuer
  markSetupComplete: (key?: string) => void
  /** Shut down background polling tasks (device_code flow). */
  shutdown: () => Promise<void>
}

const AUTH_CODE_TTL_S = 600
const SESSION_TTL_S = 600

interface PendingSession {
  clientId: string
  redirectUri: string
  state: string
  codeChallenge: string
  codeChallengeMethod: string
  createdAt: number
}

interface AuthCodeEntry {
  codeChallenge: string
  codeChallengeMethod: string
  sub: string
  createdAt: number
}

function s256Verify(codeVerifier: string, codeChallenge: string): boolean {
  const computed = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url')
  const computedBuf = Buffer.from(computed, 'ascii')
  const challengeBuf = Buffer.from(codeChallenge, 'ascii')
  const isLengthEqual = computedBuf.length === challengeBuf.length
  const compareBuf = isLengthEqual ? challengeBuf : computedBuf
  try {
    return timingSafeEqual(computedBuf, compareBuf) && isLengthEqual
  } catch {
    return false
  }
}

/**
 * Mutates ``body`` to include client credentials per the configured auth
 * method and returns any HTTP headers required to authenticate the token
 * request with the upstream endpoint.
 *
 * Default is ``client_secret_basic`` (HTTP Basic) per RFC 6749 §2.3.1 which
 * says clients MUST support basic and MAY support post. Notion / GitHub /
 * Microsoft identity platform reject ``client_secret_post`` with
 * ``invalid_client``; Google/Slack accept both. Public clients (no secret)
 * always use ``client_id`` in the body regardless of method.
 */
function buildClientAuth(body: URLSearchParams, upstream: UpstreamOAuthConfig): Record<string, string> {
  const method: TokenEndpointAuthMethod = upstream.tokenEndpointAuthMethod ?? 'client_secret_basic'
  if (!upstream.clientSecret) {
    body.set('client_id', upstream.clientId)
    return {}
  }
  if (method === 'client_secret_post') {
    body.set('client_id', upstream.clientId)
    body.set('client_secret', upstream.clientSecret)
    return {}
  }
  const encoded = Buffer.from(`${upstream.clientId}:${upstream.clientSecret}`, 'utf8').toString('base64')
  return { Authorization: `Basic ${encoded}` }
}

/**
 * Derive the public base URL of this request. See ``local-oauth-app.ts`` for
 * the resolution order; this function is the delegated-flow twin and must
 * stay in lock-step so both well-known documents agree on the issuer.
 */
function getBaseUrl(req: IncomingMessage): string {
  const publicUrl = process.env.PUBLIC_URL
  if (publicUrl !== undefined && publicUrl.length > 0) {
    return publicUrl.replace(/\/+$/, '')
  }

  const host = req.headers.host ?? 'localhost'
  const encrypted = (req.socket as { encrypted?: boolean }).encrypted === true
  const forwardedProto = req.headers['x-forwarded-proto']
  const protocol =
    typeof forwardedProto === 'string' && forwardedProto.length > 0
      ? (forwardedProto.indexOf(',') !== -1
          ? forwardedProto.substring(0, forwardedProto.indexOf(','))
          : forwardedProto
        ).trim()
      : encrypted
        ? 'https'
        : 'http'
  return `${protocol}://${host}`
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function renderDeviceCodePage(opts: { serverName: string; userCode: string; verificationUrl: string }): string {
  const safeName = escapeHtml(opts.serverName)
  const safeCode = escapeHtml(opts.userCode)
  const safeUrl = escapeHtml(opts.verificationUrl)
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Authorize ${safeName}</title>
<style>
body { font-family: system-ui, sans-serif; background: #0d0d0d; color: #eee;
       display: flex; align-items: center; justify-content: center;
       min-height: 100vh; margin: 0; }
.card { background: #181818; padding: 2rem 3rem; border-radius: 12px;
        border: 1px solid #333; max-width: 480px; text-align: center; }
h1 { margin-top: 0; }
.code { font-size: 2rem; font-family: ui-monospace, monospace;
         letter-spacing: 0.25em; padding: 1rem 1.5rem; background: #000;
         border-radius: 8px; border: 1px solid #444; margin: 1.5rem 0; }
a { color: #4ea1ff; }
.status { margin-top: 1.5rem; color: #888; font-size: 0.9rem; }
</style>
</head>
<body>
<div class="card">
  <h1>Authorize ${safeName}</h1>
  <p>Visit the URL below and enter this code:</p>
  <div class="code">${safeCode}</div>
  <p><a href="${safeUrl}" target="_blank" rel="noopener noreferrer">${safeUrl}</a></p>
  <p class="status" id="status" role="alert">Waiting for you to approve...</p>
</div>
<script>
async function poll() {
  try {
    const r = await fetch('/setup-status');
    const j = await r.json();
    const s = j[Object.keys(j)[0]] || 'idle';
    if (s === 'complete') {
      document.getElementById('status').textContent = 'Authorized! You can close this window.';
      return;
    }
    if (s === 'error') {
      document.getElementById('status').textContent = 'Authorization failed. Please restart.';
      return;
    }
  } catch (e) {}
  setTimeout(poll, 2000);
}
poll();
</script>
</body>
</html>`
}

export async function createDelegatedOAuthApp(options: DelegatedOAuthAppOptions): Promise<DelegatedOAuthAppResult> {
  if (options.flow === 'redirect' && !options.upstream.authorizeUrl) {
    throw new Error('authorizeUrl is required for redirect flow')
  }
  if (options.flow === 'device_code' && !options.upstream.deviceAuthUrl) {
    throw new Error('deviceAuthUrl is required for device_code flow')
  }

  const jwtIssuer =
    options.jwtIssuer ?? new JWTIssuer(options.serverName, undefined, process.env.CREDENTIAL_SECRET ?? null)
  await jwtIssuer.init()

  const pendingSessions = createSessionStore<PendingSession>(options.sessionKv, SESSION_TTL_S)
  const authCodes = createSessionStore<AuthCodeEntry>(options.sessionKv, AUTH_CODE_TTL_S)
  const setupStatus: Record<string, string> = { [options.serverName]: 'idle' }
  // Each entry: AbortController for the background poll loop.
  const pollControllers = new Set<AbortController>()
  const callbackPath = options.upstream.callbackPath ?? '/callback'

  // Edge auth password gate. When ``MCP_RELAY_PASSWORD`` is set, /authorize
  // is fronted by a cookie-session middleware. Empty password disables the
  // gate (single-user dev). Mirrors createLocalOAuthApp wiring; see spec
  // ``2026-05-01-stdio-pure-http-multiuser §4.2.1 + §5.1.2.1`` and PR #158.
  // Configured here (not module-scope) so multi-app test setups don't leak
  // state across apps; the relay-login module itself keeps a single shared
  // password string, intentional because in deploy each container hosts one
  // app. /token, /register, /setup-status, /callback, /.well-known/* stay
  // ungated by design — they are machine endpoints / mid-OAuth callbacks
  // that cannot be password-gated without breaking the upstream protocol.
  const relayPassword = process.env.MCP_RELAY_PASSWORD ?? ''
  configureRelayLogin(relayPassword)
  const relayMw = createRelayLoginMiddleware({ password: relayPassword })

  function markSetupComplete(key?: string): void {
    setupStatus[key ?? options.serverName] = 'complete'
  }

  function markSetupError(key?: string): void {
    setupStatus[key ?? options.serverName] = 'error'
  }

  async function invokeTokenCallback(tokens: OAuthTokens): Promise<string> {
    const result = await options.onTokenReceived(tokens)
    return typeof result === 'string' && result.length > 0 ? result : 'local-user'
  }

  // ------------------------------------------------------------------
  // Redirect flow
  // ------------------------------------------------------------------

  async function authorizeRedirect(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const p = url.searchParams
    const clientId = p.get('client_id')
    const redirectUri = p.get('redirect_uri')
    const state = p.get('state')
    const codeChallenge = p.get('code_challenge')
    const codeChallengeMethod = p.get('code_challenge_method') ?? 'S256'

    if (!clientId || !redirectUri || !state || !codeChallenge) {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Missing required parameters'
      })
      return
    }

    const nonce = randomBytes(32).toString('base64url')
    await pendingSessions.set(nonce, {
      clientId,
      redirectUri,
      state,
      codeChallenge,
      codeChallengeMethod,
      createdAt: Date.now()
    })

    const base = getBaseUrl(req)
    const qs = new URLSearchParams({
      client_id: options.upstream.clientId,
      redirect_uri: `${base}${callbackPath}`,
      response_type: 'code',
      state: nonce
    })
    if (options.upstream.scopes && options.upstream.scopes.length > 0) {
      qs.set('scope', options.upstream.scopes.join(' '))
    }
    const authorizeUrl = options.upstream.authorizeUrl as string
    const separator = authorizeUrl.includes('?') ? '&' : '?'
    const target = `${authorizeUrl}${separator}${qs.toString()}`
    res.writeHead(302, { Location: target })
    res.end()
  }

  async function callback(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')

    if (!code || !state) {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Missing code or state'
      })
      return
    }

    const session = await pendingSessions.get(state)
    if (session === undefined) {
      jsonResponse(res, 400, { error: 'invalid_request', error_description: 'Invalid state' })
      return
    }
    await pendingSessions.delete(state)

    const base = getBaseUrl(req)
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: `${base}${callbackPath}`
    })
    const authHeaders = buildClientAuth(form, options.upstream)

    let upstreamResp: Response
    try {
      upstreamResp = await fetch(options.upstream.tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
          ...authHeaders
        },
        body: form.toString()
      })
    } catch {
      jsonResponse(res, 502, {
        error: 'server_error',
        error_description: 'Upstream token exchange failed'
      })
      return
    }

    if (!upstreamResp.ok) {
      const text = await upstreamResp.text().catch(() => '')
      jsonResponse(res, 400, {
        error: 'invalid_grant',
        error_description: `Upstream rejected token exchange: ${text}`
      })
      return
    }

    let tokens: OAuthTokens
    try {
      tokens = (await upstreamResp.json()) as OAuthTokens
    } catch {
      jsonResponse(res, 502, {
        error: 'server_error',
        error_description: 'Upstream returned invalid JSON'
      })
      return
    }

    let sub: string
    try {
      sub = await invokeTokenCallback(tokens)
    } catch {
      jsonResponse(res, 500, {
        error: 'server_error',
        error_description: 'Failed to persist tokens'
      })
      return
    }

    const authCode = randomBytes(32).toString('base64url')
    await authCodes.set(authCode, {
      codeChallenge: session.codeChallenge,
      codeChallengeMethod: session.codeChallengeMethod,
      sub,
      createdAt: Date.now()
    })

    const separator = session.redirectUri.includes('?') ? '&' : '?'
    const redirectUrl = `${session.redirectUri}${separator}code=${authCode}&state=${session.state}`
    res.writeHead(302, { Location: redirectUrl })
    res.end()
  }

  // ------------------------------------------------------------------
  // Device code flow
  // ------------------------------------------------------------------

  async function pollDeviceToken(
    deviceCode: string,
    initialIntervalMs: number,
    controller: AbortController,
    authCode: string
  ): Promise<void> {
    let intervalMs = Math.max(initialIntervalMs, 0)
    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: deviceCode
    })
    const authHeaders = buildClientAuth(body, options.upstream)

    while (!controller.signal.aborted) {
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, intervalMs)
        controller.signal.addEventListener(
          'abort',
          () => {
            clearTimeout(t)
            resolve()
          },
          { once: true }
        )
      })
      if (controller.signal.aborted) return

      let resp: Response
      try {
        resp = await fetch(options.upstream.tokenUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json',
            ...authHeaders
          },
          body: body.toString(),
          signal: controller.signal
        })
      } catch {
        if (controller.signal.aborted) return
        markSetupError()
        return
      }

      if (resp.ok) {
        let tokens: OAuthTokens
        try {
          tokens = (await resp.json()) as OAuthTokens
        } catch {
          markSetupError()
          return
        }
        let sub: string
        try {
          sub = await invokeTokenCallback(tokens)
        } catch {
          markSetupError()
          return
        }
        // Update pre-allocated authCode entry with real subject.
        const entry = await authCodes.get(authCode)
        if (entry) {
          entry.sub = sub
          await authCodes.set(authCode, entry)
        }
        markSetupComplete()
        return
      }

      let errBody: Record<string, unknown>
      try {
        errBody = (await resp.json()) as Record<string, unknown>
      } catch {
        markSetupError()
        return
      }
      const err = errBody.error
      if (err === 'authorization_pending') continue
      if (err === 'slow_down') {
        intervalMs += 5000
        continue
      }
      markSetupError()
      return
    }
  }

  async function authorizeDeviceCode(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const p = url.searchParams
    const clientId = p.get('client_id')
    const redirectUri = p.get('redirect_uri')
    const state = p.get('state')
    const codeChallenge = p.get('code_challenge')
    const codeChallengeMethod = p.get('code_challenge_method') ?? 'S256'

    if (!clientId || !redirectUri || !state || !codeChallenge) {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Missing required parameters'
      })
      return
    }

    // Initiate upstream device authorization.
    const body = new URLSearchParams({ client_id: options.upstream.clientId })
    if (options.upstream.scopes && options.upstream.scopes.length > 0) {
      body.set('scope', options.upstream.scopes.join(' '))
    }

    let upstreamResp: Response
    try {
      upstreamResp = await fetch(options.upstream.deviceAuthUrl as string, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString()
      })
    } catch {
      jsonResponse(res, 502, {
        error: 'server_error',
        error_description: 'Upstream device auth failed'
      })
      return
    }

    if (!upstreamResp.ok) {
      const text = await upstreamResp.text().catch(() => '')
      jsonResponse(res, 502, {
        error: 'server_error',
        error_description: `Upstream device auth rejected: ${text}`
      })
      return
    }

    let device: Record<string, unknown>
    try {
      device = (await upstreamResp.json()) as Record<string, unknown>
    } catch {
      jsonResponse(res, 502, {
        error: 'server_error',
        error_description: 'Upstream device auth returned invalid JSON'
      })
      return
    }

    const deviceCode = typeof device.device_code === 'string' ? device.device_code : undefined
    const userCode = typeof device.user_code === 'string' ? device.user_code : undefined
    const verificationUrl =
      typeof device.verification_url === 'string'
        ? device.verification_url
        : typeof device.verification_uri === 'string'
          ? device.verification_uri
          : undefined
    const intervalSecs =
      typeof device.interval === 'number'
        ? device.interval
        : Math.max((options.upstream.pollIntervalMs ?? 5000) / 1000, 1)

    if (!deviceCode || !userCode || !verificationUrl) {
      jsonResponse(res, 502, {
        error: 'server_error',
        error_description: 'Upstream device auth response missing fields'
      })
      return
    }

    // Pre-allocate auth code so /token can complete once polling succeeds.
    // `sub` is a placeholder; pollDeviceToken updates it after
    // invokeTokenCallback returns the real subject id.
    const authCode = randomBytes(32).toString('base64url')
    await authCodes.set(authCode, {
      codeChallenge,
      codeChallengeMethod,
      sub: 'local-user',
      createdAt: Date.now()
    })

    setupStatus[options.serverName] = 'pending'
    const controller = new AbortController()
    pollControllers.add(controller)
    // Run in background; intentionally not awaited.
    pollDeviceToken(deviceCode, intervalSecs * 1000, controller, authCode).finally(() => {
      pollControllers.delete(controller)
    })

    htmlResponse(
      res,
      200,
      renderDeviceCodePage({
        serverName: options.serverName,
        userCode,
        verificationUrl
      })
    )
  }

  // ------------------------------------------------------------------
  // Shared endpoints
  // ------------------------------------------------------------------

  async function authorize(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (options.flow === 'redirect') {
      await authorizeRedirect(req, res)
      return
    }
    await authorizeDeviceCode(req, res)
  }

  /**
   * Build and write the standard /token success body for ``sub``.
   *
   * Issues a fresh access token AND a fresh refresh token. The refresh token
   * lets long-running MCP clients renew the 1h access token without re-running
   * the upstream OAuth flow (issue #261). ``scope`` advertises ``offline_access``
   * so clients know a refresh token was granted. The local refresh token is
   * keyed only on ``sub`` -- it does NOT carry upstream provider tokens;
   * consumers that need upstream refresh manage that via ``onTokenReceived``.
   */
  async function issueTokenResponse(res: ServerResponse, sub: string): Promise<void> {
    const accessToken = await jwtIssuer.issueAccessToken(sub)
    const refreshToken = await jwtIssuer.issueRefreshToken(sub)
    jsonResponse(res, 200, {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: 'offline_access'
    })
  }

  /**
   * Handle ``grant_type=refresh_token`` (RFC 6749 §6) statelessly. Verifies the
   * presented refresh token's signature / iss / aud / exp / ``typ`` via the JWT
   * issuer (no server-side store), extracts ``sub``, and issues a NEW access
   * token AND a NEW refresh token (rotation). The refresh token is
   * self-contained, so rotation here is stateless: the old refresh token simply
   * expires on its own 30-day clock.
   */
  async function handleRefreshToken(res: ServerResponse, form: Record<string, string>): Promise<void> {
    const refreshToken = form.refresh_token
    if (!refreshToken) {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Missing refresh_token'
      })
      return
    }
    let sub: string
    try {
      const claims = await jwtIssuer.verifyRefreshToken(refreshToken)
      sub = claims.sub as string
    } catch {
      jsonResponse(res, 400, { error: 'invalid_grant' })
      return
    }
    await issueTokenResponse(res, sub)
  }

  async function token(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let form: Record<string, string>
    try {
      form = await parseFormBody(req)
    } catch {
      jsonResponse(res, 400, { error: 'invalid_request' })
      return
    }

    if (form.grant_type === 'refresh_token') {
      await handleRefreshToken(res, form)
      return
    }
    if (form.grant_type !== 'authorization_code') {
      jsonResponse(res, 400, { error: 'unsupported_grant_type' })
      return
    }

    const code = form.code
    const codeVerifier = form.code_verifier
    if (!code || !codeVerifier) {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Missing code or code_verifier'
      })
      return
    }

    const entry = await authCodes.get(code)
    if (entry === undefined) {
      jsonResponse(res, 400, { error: 'invalid_grant' })
      return
    }
    await authCodes.delete(code)

    if (entry.codeChallengeMethod !== 'S256') {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Only S256 is supported'
      })
      return
    }

    if (!s256Verify(codeVerifier, entry.codeChallenge)) {
      jsonResponse(res, 400, { error: 'invalid_grant' })
      return
    }

    await issueTokenResponse(res, entry.sub)
  }

  async function setupStatusHandler(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    jsonResponse(res, 200, setupStatus)
  }

  async function wellKnownAs(req: IncomingMessage, res: ServerResponse): Promise<void> {
    jsonResponse(res, 200, authorizationServerMetadata(getBaseUrl(req)))
  }

  /**
   * RFC 7591 Dynamic Client Registration.
   *
   * Since this server accepts a fixed public client id (`local-browser`)
   * with no per-client credentials, DCR echoes back whatever
   * ``redirect_uris`` / grant types the client submitted and returns
   * the fixed id. This satisfies MCP clients that refuse to speak OAuth
   * without DCR (e.g. Python SDK ``OAuthClientProvider``).
   */
  async function registerHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let body: Record<string, unknown> = {}
    try {
      const raw = await parseJsonBody(req)
      body = raw as Record<string, unknown>
    } catch {
      // fall through with empty body; clients can still get defaults
    }
    const redirectUris = Array.isArray(body.redirect_uris) ? (body.redirect_uris as string[]) : []
    const grantTypes = Array.isArray(body.grant_types) ? (body.grant_types as string[]) : ['authorization_code']
    const responseTypes = Array.isArray(body.response_types) ? (body.response_types as string[]) : ['code']
    const clientName = typeof body.client_name === 'string' ? body.client_name : 'mcp-client'
    jsonResponse(res, 201, {
      client_id: 'local-browser',
      client_name: clientName,
      redirect_uris: redirectUris,
      grant_types: grantTypes,
      response_types: responseTypes,
      token_endpoint_auth_method: 'none'
    })
  }

  async function wellKnownPr(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const base = getBaseUrl(req)
    jsonResponse(res, 200, protectedResourceMetadata(base, [base]))
  }

  async function wellKnownJwks(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    jsonResponse(res, 200, await jwtIssuer.getJwks())
  }

  /**
   * GET / -- auto-generate PKCE and redirect to /authorize.
   *
   * Parity with createLocalOAuthApp's rootHandler. Users arriving from a
   * bookmark / log line at the bare server URL get a usable OAuth flow
   * without having to construct PKCE params manually. The delegated
   * /authorize endpoint validates these params against its delegated
   * upstream configuration, so using "local-browser" as client_id works
   * for both redirect and device_code flows.
   */
  async function rootHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const base = getBaseUrl(req)
    const codeVerifier = randomBytes(64).toString('base64url')
    const codeChallenge = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url')
    const state = randomBytes(16).toString('base64url')

    const params = new URLSearchParams({
      client_id: 'local-browser',
      redirect_uri: `${base}/callback-done`,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    })
    res.writeHead(302, { Location: `/authorize?${params.toString()}` })
    res.end()
  }

  /**
   * GET /callback-done -- terminal "tab can be closed" landing page.
   * Mirrors createLocalOAuthApp so the redirect target from rootHandler
   * resolves to a friendly message instead of 404 when the user finishes
   * the delegated OAuth flow.
   */
  async function callbackDoneHandler(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    const html =
      "<!DOCTYPE html><html><head><meta charset='utf-8'>" +
      '<title>Setup complete</title>' +
      '<style>body{font-family:-apple-system,Segoe UI,sans-serif;' +
      'background:#111;color:#eee;display:flex;align-items:center;' +
      'justify-content:center;height:100vh;margin:0}' +
      '.box{text-align:center;padding:2rem;border:1px solid #333;' +
      'border-radius:8px;background:#1a1a1a}' +
      'h1{color:#34c759;margin:0 0 0.5rem}p{color:#aaa;margin:0}' +
      '</style></head><body><div class="box">' +
      '<h1>Setup complete</h1>' +
      '<p>You can close this tab.</p>' +
      '</div></body></html>'
    htmlResponse(res, 200, html)
  }

  // ------------------------------------------------------------------
  // Relay password gate adapters.
  //
  // Mirrors createLocalOAuthApp's adapter block. The relay-login module
  // exposes Express-style handlers (``req.body``, ``res.status().send()``);
  // here we adapt them onto the project's ``IncomingMessage`` /
  // ``ServerResponse`` router. Only ``/authorize`` GET goes through
  // ``relayMw``; ``/token``, ``/register``, ``/setup-status``, ``/callback``,
  // ``/.well-known/*``, ``/`` and ``/callback-done`` are intentionally NOT
  // gated — they're machine endpoints (DCR / token exchange / metadata),
  // mid-OAuth callbacks (``/callback`` is hit by the upstream provider, not
  // a logged-in user), or auto-bootstrap helpers.
  // ------------------------------------------------------------------

  function parseCookies(req: IncomingMessage): Record<string, string> {
    const header = req.headers.cookie
    if (!header) return {}
    const out: Record<string, string> = {}

    // ⚡ Bolt: Use a single-pass loop instead of `split(';')` to avoid array
    // allocations and intermediate string objects in this hot path.
    let pos = 0
    while (pos < header.length) {
      let nextSemi = header.indexOf(';', pos)
      if (nextSemi < 0) nextSemi = header.length

      const eq = header.indexOf('=', pos)
      if (eq >= 0 && eq < nextSemi) {
        const k = header.substring(pos, eq).trim()
        const v = header.substring(eq + 1, nextSemi).trim()
        if (k.length > 0) out[k] = decodeURIComponent(v)
      }

      pos = nextSemi + 1
    }
    return out
  }

  function clientIp(req: IncomingMessage): string {
    const fwd = req.headers['x-forwarded-for']
    if (typeof fwd === 'string' && fwd.length > 0) {
      const idx = fwd.indexOf(',')
      return (idx !== -1 ? fwd.substring(0, idx) : fwd).trim()
    }
    return req.socket.remoteAddress ?? 'unknown'
  }

  function buildResAdapter(res: ServerResponse): {
    adapter: Record<string, (...args: unknown[]) => unknown>
    isComplete: () => boolean
  } {
    let statusCode = 200
    const headers: Record<string, string> = {}
    let completed = false
    const setHeader = (name: string, value: string): void => {
      headers[name] = value
    }
    const adapter: Record<string, (...args: unknown[]) => unknown> = {
      status: (code: unknown) => {
        statusCode = Number(code)
        return adapter
      },
      header: (name: unknown, value: unknown) => {
        setHeader(String(name), String(value))
        return adapter
      },
      set: (name: unknown, value: unknown) => {
        setHeader(String(name), String(value))
        return adapter
      },
      cookie: (name: unknown, value: unknown, options: unknown) => {
        const opts = (options ?? {}) as Record<string, unknown>
        const parts: string[] = [`${String(name)}=${String(value)}`]
        if (opts.maxAge !== undefined) {
          parts.push(`Max-Age=${Math.floor(Number(opts.maxAge) / 1000)}`)
        }
        if (opts.httpOnly === true) parts.push('HttpOnly')
        if (opts.secure === true) parts.push('Secure')
        if (typeof opts.sameSite === 'string') {
          const v = opts.sameSite as string
          parts.push(`SameSite=${v.charAt(0).toUpperCase() + v.slice(1)}`)
        }
        parts.push('Path=/')
        const existing = headers['Set-Cookie']
        const next = parts.join('; ')
        headers['Set-Cookie'] = existing !== undefined ? `${existing}, ${next}` : next
        return adapter
      },
      send: (body: unknown) => {
        if (completed) return adapter
        completed = true
        if (!('Content-Type' in headers)) {
          headers['Content-Type'] = 'text/html; charset=utf-8'
        }

        // Anti-clickjacking for HTML responses
        const ctype = headers['Content-Type'] as string
        if (ctype && ctype.toLowerCase().includes('text/html')) {
          headers['X-Frame-Options'] = 'DENY'
        }

        res.writeHead(statusCode, headers)
        res.end(body === undefined ? '' : String(body))
        return adapter
      },
      redirect: (url: unknown) => {
        if (completed) return adapter
        completed = true
        headers.Location = String(url)
        res.writeHead(302, headers)
        res.end()
        return adapter
      }
    }
    return { adapter, isComplete: () => completed }
  }

  /**
   * Wrap a router handler with the relay-login middleware. If the cookie
   * gate redirects, the inner handler is never called; otherwise the inner
   * handler runs against the original ``req`` / ``res``.
   */
  function withRelayGate(inner: RequestHandler): RequestHandler {
    return async (req, res) => {
      if (!relayPassword) {
        await inner(req, res)
        return
      }
      const cookies = parseCookies(req)
      const expressReq = {
        cookies,
        originalUrl: req.url ?? '/'
      }
      const { adapter, isComplete } = buildResAdapter(res)
      let proceed = false
      await relayMw(expressReq as never, adapter as never, () => {
        proceed = true
      })
      if (proceed && !isComplete()) {
        await inner(req, res)
      }
    }
  }

  async function loginGetRoute(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const expressReq = { query: { next: url.searchParams.get('next') ?? '/authorize' } }
    const { adapter } = buildResAdapter(res)
    await loginGetHandler(expressReq as never, adapter as never)
  }

  async function loginPostRoute(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let body: Record<string, string> = {}
    try {
      body = await parseFormBody(req)
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'invalid_request' }))
      return
    }
    const expressReq = { body, ip: clientIp(req) }
    const { adapter } = buildResAdapter(res)
    await loginPostHandler(expressReq as never, adapter as never)
  }

  const routes: Parameters<typeof createRouter>[0] = [
    { method: 'GET', path: '/', handler: rootHandler },
    { method: 'GET', path: '/callback-done', handler: callbackDoneHandler },
    { method: 'GET', path: '/login', handler: loginGetRoute },
    { method: 'POST', path: '/login', handler: loginPostRoute },
    { method: 'GET', path: '/authorize', handler: withRelayGate(authorize) },
    { method: 'POST', path: '/token', handler: token },
    { method: 'POST', path: '/register', handler: registerHandler },
    { method: 'GET', path: '/setup-status', handler: setupStatusHandler },
    { method: 'GET', path: '/.well-known/oauth-authorization-server', handler: wellKnownAs },
    { method: 'GET', path: '/.well-known/oauth-protected-resource', handler: wellKnownPr },
    { method: 'GET', path: '/.well-known/jwks.json', handler: wellKnownJwks }
  ]
  if (options.flow === 'redirect') {
    routes.push({ method: 'GET', path: callbackPath, handler: callback })
  }

  const handler = createRouter(routes)

  async function shutdown(): Promise<void> {
    for (const controller of pollControllers) {
      controller.abort()
    }
    pollControllers.clear()
  }

  return { handler, jwtIssuer, markSetupComplete, shutdown }
}
