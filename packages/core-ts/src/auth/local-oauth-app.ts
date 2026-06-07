/**
 * MCP Relay Local OAuth Server.
 *
 * Implements a minimal RFC 6749 / 2.1 authorization server on top of Node.js
 * ``http.IncomingMessage`` / ``ServerResponse``. Provides the browser-based
 * credential collection and Bearer token issuance used by MCP transports.
 *
 * Routes:
 * - GET  /                                         -- PKCE Bootstrap redirect
 * - GET  /login                                    -- Relay password entry page
 * - POST /login                                    -- Relay password submission
 * - GET  /authorize                                -- Render credential form
 * - POST /authorize                                -- Submit credentials, return auth code
 * - POST /otp                                      -- Submit multi-step credential (OTP / 2FA password)
 * - POST /token                                    -- Exchange auth code + PKCE verifier for JWT
 * - GET  /setup-status                             -- Poll background setup completion
 * - GET  /callback-done                            -- Friendly "tab can be closed" page after PKCE callback
 * - GET  /.well-known/oauth-authorization-server   -- RFC 8414 metadata
 * - GET  /.well-known/oauth-protected-resource     -- RFC 9728 metadata
 *
 * The /mcp endpoint is NOT included -- it is mounted by the transport layer.
 *
 * This is a TypeScript port of core-py's ``local_oauth_app.py``. Behavior,
 * protocol, and TTL constants are kept identical for cross-language parity.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { JWTIssuer } from '../oauth/jwt-issuer.js'
import { markSetupComplete as markConfigSetupComplete } from '../storage/config-file.js'
import {
  isOAuthField,
  isSecretField,
  type RelayConfigField,
  type RelayConfigSchema,
  renderCredentialForm
} from './credential-form.js'
import { configureRelayLogin, createRelayLoginMiddleware, loginGetHandler, loginPostHandler } from './relay-login.js'
import {
  createRouter,
  htmlResponse,
  jsonResponse,
  parseFormBody,
  parseJsonBody,
  type RequestHandler
} from './router.js'
import { authorizationServerMetadata, protectedResourceMetadata } from './well-known.js'

/** Next-step hint returned by credential / step callbacks. */
export type NextStep = Record<string, unknown>

/**
 * Context passed to credential / step callbacks so the consumer can scope
 * stored credentials by subject (JWT ``sub``). Generated fresh per GET
 * /authorize and reused for the subsequent POST /authorize + /token exchange,
 * so the JWT issued after credential save carries the SAME ``sub`` the
 * consumer used to persist the credentials. This is the primitive that
 * enables multi-user isolation for `remote-relay` mode: without it consumers
 * had to fall back to a single shared `config.enc`, leaking credentials
 * across concurrent browser sessions.
 */
export interface SubjectContext {
  /** Per-authorize-request UUID, also becomes the JWT ``sub`` after /token. */
  sub: string
}

/**
 * Callback invoked when the user submits credentials via POST /authorize.
 *
 * Receives the submitted credential map + the authorize-session ``SubjectContext``
 * so the consumer can persist credentials keyed by ``sub``. Return ``null`` to
 * finish the flow or a ``next_step`` dict to trigger a follow-up (OAuth
 * device code, OTP, 2FA password, etc). May be sync or async.
 *
 * Consumers that don't need multi-user isolation (stdio fallback, local-relay
 * single-user mode) can ignore the ``context`` parameter.
 */
export type CredentialsCallback = (
  creds: Record<string, string>,
  context: SubjectContext
) => NextStep | null | Promise<NextStep | null>

/**
 * Callback invoked when the user submits step input via POST /otp.
 *
 * Receives the submitted step data + the authorize-session ``SubjectContext``
 * so multi-step flows (OTP, 2FA password) can route the input to the correct
 * per-user state — e.g. the Telethon client that started the sign-in under
 * this ``sub``. Without this, consumers would be forced to keep a single
 * global "currently auth'ing user" and concurrent remote-relay users would
 * corrupt each other's 2FA flow.
 *
 * Return ``null`` to complete the flow, a ``{type: "otp_required" |
 * "password_required", ...}`` dict to chain to another step, or
 * ``{type: "error", text: "..."}`` to reject the current input and allow
 * retry. Callbacks comparing secrets MUST use a timing-safe comparison.
 * May be sync or async.
 */
export type StepCallback = (
  data: Record<string, string>,
  context: SubjectContext
) => NextStep | null | Promise<NextStep | null>

export interface LocalOAuthAppOptions {
  /** Identifier for the MCP server (used for JWT iss / aud). */
  serverName: string
  /** RelayConfigSchema describing the credential form. */
  relaySchema: RelayConfigSchema
  /** Optional callback invoked with credentials after POST /authorize. */
  onCredentialsSaved?: CredentialsCallback
  /** Optional callback invoked with step data after POST /otp. */
  onStepSubmitted?: StepCallback
  /** Optional pre-created JWT issuer. If omitted, one is created automatically. */
  jwtIssuer?: JWTIssuer
  /**
   * Optional renderer used in place of the default credential form on GET
   * /authorize. Receives the relay schema and an options object with
   * ``submitUrl`` (which embeds the PKCE nonce) plus an optional ``prefill``
   * mapping carrying skret-derived field values from
   * ``?prefill_<KEY>=<VALUE>`` query params. Consumers (email, telegram)
   * use this to inject rich UX while reusing core OAuth plumbing; renderers
   * may safely ignore ``prefill`` if they don't display matching inputs.
   */
  customCredentialFormHtml?: (
    schema: RelayConfigSchema,
    options: { submitUrl: string; prefill?: Record<string, string> }
  ) => string
}

export interface LocalOAuthAppResult {
  /** HTTP request handler to mount on a Node ``http.Server``. */
  handler: RequestHandler
  /** JWT issuer, needed by the transport layer to verify Bearer tokens. */
  jwtIssuer: JWTIssuer
  /** Mark a background setup step as complete (polled by GET /setup-status). */
  markSetupComplete: (key?: string) => void
  /**
   * Mark a background setup step as failed (polled by GET /setup-status).
   * Encodes the status as ``"error:<message>"`` so the browser poll handler
   * can distinguish success, failure, and still-pending states without
   * spinning forever on upstream errors (e.g. Google returning
   * ``invalid_grant`` / ``expired_token`` / ``access_denied``).
   */
  markSetupFailed: (key?: string, error?: string) => void
}

// Auth codes and PKCE sessions expire after 10 minutes.
const AUTH_CODE_TTL_S = 600
const SESSION_TTL_S = 600

// Multi-step auth (OTP / 2FA password) constraints.
const OTP_TIMEOUT_S = 300
const OTP_MAX_ATTEMPTS = 5

interface PendingSession {
  clientId: string
  redirectUri: string
  state: string
  codeChallenge: string
  codeChallengeMethod: string
  createdAt: number
  /**
   * Per-authorize-request subject. Generated fresh when GET /authorize renders
   * the form; carried through POST /authorize (passed to onCredentialsSaved)
   * and POST /token (used as JWT ``sub``) so credentials saved under this
   * subject are reachable via the issued Bearer token.
   */
  sub: string
}

interface AuthCodeEntry {
  codeChallenge: string
  codeChallengeMethod: string
  createdAt: number
  /** JWT subject to issue at /token. Copied from PendingSession.sub. */
  sub: string
}

interface PendingStep {
  active: boolean
  createdAt: number
  attempts: number
  /**
   * Subject that opened this multi-step session (via onCredentialsSaved
   * returning ``otp_required`` / ``password_required``). OTP submissions
   * have no body sub, so the handler uses this field to thread the correct
   * ``SubjectContext`` into ``onStepSubmitted``.
   */
  sub: string
}

/**
 * Verify PKCE S256: ``base64url(sha256(code_verifier)) == code_challenge``,
 * using a timing-safe comparison to prevent timing attacks.
 */
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

/** Prune entries older than ``ttlMs`` milliseconds from an in-memory store. */
function pruneExpired<T extends { createdAt: number }>(store: Map<string, T>, ttlMs: number): void {
  const now = Date.now()
  for (const [key, value] of store) {
    if (now - value.createdAt > ttlMs) store.delete(key)
  }
}

/**
 * Derive the public base URL of this request (protocol + host, no trailing slash).
 *
 * Resolution order:
 * 1. ``PUBLIC_URL`` env var -- trusted, explicit. This is the remote-deploy
 *    convention (oci-vm-prod) where the container sits behind CF Tunnel ->
 *    Caddy (HTTP internal) but is served to clients over HTTPS. Without this,
 *    OAuth 2.1 metadata would leak ``http://`` as the issuer and strict
 *    clients reject the discovery document.
 * 2. ``X-Forwarded-Proto`` header (first value) + Host header -- for reverse
 *    proxies that forward the original scheme.
 * 3. Socket ``encrypted`` flag -- TLS-terminated at this process.
 * 4. ``http://<host>`` fallback -- plain local dev.
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
      ? forwardedProto.split(',')[0].trim()
      : encrypted
        ? 'https'
        : 'http'
  return `${protocol}://${host}`
}

/**
 * Private class encapsulating the local OAuth server logic.
 */
class LocalOAuthServer {
  private readonly options: LocalOAuthAppOptions
  public readonly jwtIssuer: JWTIssuer
  private readonly pendingSessions = new Map<string, PendingSession>()
  private readonly authCodes = new Map<string, AuthCodeEntry>()
  private readonly pendingPrefills = new Map<string, { data: Record<string, string>; createdAt: number }>()
  private readonly PREFILL_TTL_S = 300
  private pendingStep: PendingStep | null = null
  private readonly setupStatus: Record<string, string> = { gdrive: 'idle' }
  private readonly relayPassword = process.env.MCP_RELAY_PASSWORD ?? ''
  private readonly relayMw: ReturnType<typeof createRelayLoginMiddleware>

  constructor(options: LocalOAuthAppOptions) {
    this.options = options
    this.jwtIssuer = options.jwtIssuer ?? new JWTIssuer(options.serverName)
    configureRelayLogin(this.relayPassword)
    this.relayMw = createRelayLoginMiddleware({ password: this.relayPassword })
  }

  async init(): Promise<void> {
    await this.jwtIssuer.init()
  }

  private markPendingStep(sub: string): void {
    this.pendingStep = { active: true, createdAt: Date.now(), attempts: 0, sub }
  }

  private clearPendingStep(): void {
    this.pendingStep = null
  }

  async authorizeGet(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const params = url.searchParams
    const clientId = params.get('client_id')
    const redirectUri = params.get('redirect_uri')
    const state = params.get('state')
    const codeChallenge = params.get('code_challenge')
    const codeChallengeMethod = params.get('code_challenge_method') ?? 'S256'

    if (!clientId || !redirectUri || !state || !codeChallenge) {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Missing required parameters'
      })
      return
    }

    const prefill: Record<string, string> = {}
    pruneExpired(this.pendingPrefills, this.PREFILL_TTL_S * 1000)
    const stored = this.pendingPrefills.get(state)
    if (stored) {
      for (const [k, v] of Object.entries(stored.data)) {
        prefill[k] = String(v)
      }
      this.pendingPrefills.delete(state)
    } else {
      params.forEach((value, key) => {
        if (key.startsWith('prefill_')) {
          prefill[key.slice('prefill_'.length)] = value
        }
      })
    }

    const nonce = randomBytes(32).toString('base64url')
    const sub = randomBytes(16).toString('base64url')
    this.pendingSessions.set(nonce, {
      clientId,
      redirectUri,
      state,
      codeChallenge,
      codeChallengeMethod,
      createdAt: Date.now(),
      sub
    })
    pruneExpired(this.pendingSessions, SESSION_TTL_S * 1000)

    const base = getBaseUrl(req)
    const submitUrl = `${base}/authorize?nonce=${nonce}`
    const html =
      this.options.customCredentialFormHtml !== undefined
        ? this.options.customCredentialFormHtml(this.options.relaySchema, { submitUrl, prefill })
        : renderCredentialForm(this.options.relaySchema, { submitUrl, prefill })
    htmlResponse(res, 200, html)
  }

  async authorizePost(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const nonce = url.searchParams.get('nonce')
    if (!nonce || !this.pendingSessions.has(nonce)) {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Invalid or expired nonce'
      })
      return
    }

    const session = this.pendingSessions.get(nonce) as PendingSession
    this.pendingSessions.delete(nonce)

    if (Date.now() - session.createdAt > SESSION_TTL_S * 1000) {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Session expired'
      })
      return
    }

    let credentials: Record<string, string>
    try {
      credentials = await parseJsonBody<Record<string, string>>(req)
    } catch {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Body must be JSON object'
      })
      return
    }

    for (const key of Object.keys(this.setupStatus)) {
      this.setupStatus[key] = 'idle'
    }

    const context: SubjectContext = { sub: session.sub }
    let nextStep: NextStep | null = null
    if (this.options.onCredentialsSaved !== undefined) {
      try {
        const result = await this.options.onCredentialsSaved(credentials, context)
        if (result !== null && result !== undefined && typeof result === 'object') {
          nextStep = result
        }
      } catch (err) {
        jsonResponse(res, 500, {
          error: 'server_error',
          error_description: err instanceof Error ? err.message : String(err)
        })
        return
      }
    }

    if (nextStep === null) {
      try {
        await markConfigSetupComplete(this.options.serverName)
      } catch (err) {
        console.warn(
          'Failed to mark _setup_complete=true for %s: %s',
          this.options.serverName,
          err instanceof Error ? err.message : String(err)
        )
      }
    }

    const code = randomBytes(32).toString('base64url')
    this.authCodes.set(code, {
      codeChallenge: session.codeChallenge,
      codeChallengeMethod: session.codeChallengeMethod,
      createdAt: Date.now(),
      sub: session.sub
    })
    pruneExpired(this.authCodes, AUTH_CODE_TTL_S * 1000)

    const params = new URLSearchParams({
      code,
      state: session.state
    })
    const body: Record<string, unknown> = {
      ok: true,
      redirect_url: `${session.redirectUri}?${params.toString()}`
    }
    if (nextStep !== null) {
      body.next_step = nextStep
      const stepType = nextStep.type
      if (stepType === 'otp_required' || stepType === 'password_required') {
        this.markPendingStep(session.sub)
      }
    }
    jsonResponse(res, 200, body)
  }

  async authorize(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === 'GET') {
      await this.authorizeGet(req, res)
      return
    }
    await this.authorizePost(req, res)
  }

  async authorizePrefill(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const state = url.searchParams.get('state')
    if (!state) {
      jsonResponse(res, 400, { error: 'invalid_request', error_description: 'Missing state' })
      return
    }
    let body: Record<string, string>
    try {
      body = await parseJsonBody<Record<string, string>>(req)
    } catch {
      jsonResponse(res, 400, { error: 'invalid_request', error_description: 'Body must be JSON object' })
      return
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      jsonResponse(res, 400, { error: 'invalid_request', error_description: 'Body must be JSON object' })
      return
    }
    const data: Record<string, string> = {}
    for (const [k, v] of Object.entries(body)) {
      if (v != null && String(v).length > 0) {
        data[k] = String(v)
      }
    }
    this.pendingPrefills.set(state, { data, createdAt: Date.now() })
    pruneExpired(this.pendingPrefills, this.PREFILL_TTL_S * 1000)
    jsonResponse(res, 204, {})
  }

  private async issueTokenResponse(res: ServerResponse, sub: string): Promise<void> {
    const accessToken = await this.jwtIssuer.issueAccessToken(sub)
    const refreshToken = await this.jwtIssuer.issueRefreshToken(sub)
    jsonResponse(res, 200, {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: 'offline_access'
    })
  }

  private async handleRefreshToken(res: ServerResponse, form: Record<string, string>): Promise<void> {
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
      const claims = await this.jwtIssuer.verifyRefreshToken(refreshToken)
      sub = claims.sub as string
    } catch {
      jsonResponse(res, 400, { error: 'invalid_grant' })
      return
    }
    await this.issueTokenResponse(res, sub)
  }

  async token(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let form: Record<string, string>
    try {
      form = await parseFormBody(req)
    } catch {
      jsonResponse(res, 400, { error: 'invalid_request' })
      return
    }

    const grantType = form.grant_type
    if (grantType === 'refresh_token') {
      await this.handleRefreshToken(res, form)
      return
    }
    if (grantType !== 'authorization_code') {
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

    const entry = this.authCodes.get(code)
    if (entry === undefined) {
      jsonResponse(res, 400, { error: 'invalid_grant' })
      return
    }
    this.authCodes.delete(code)

    if (Date.now() - entry.createdAt > AUTH_CODE_TTL_S * 1000) {
      jsonResponse(res, 400, { error: 'invalid_grant' })
      return
    }

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

    await this.issueTokenResponse(res, entry.sub)
  }

  async otpHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (this.pendingStep === null || !this.pendingStep.active) {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'No active step session'
      })
      return
    }

    if (Date.now() - this.pendingStep.createdAt > OTP_TIMEOUT_S * 1000) {
      this.clearPendingStep()
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Step session expired'
      })
      return
    }

    let stepData: Record<string, string>
    try {
      stepData = await parseJsonBody<Record<string, string>>(req)
    } catch {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Invalid JSON body'
      })
      return
    }

    this.pendingStep.attempts += 1

    if (this.pendingStep.attempts > OTP_MAX_ATTEMPTS) {
      this.clearPendingStep()
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Too many attempts'
      })
      return
    }

    const stepContext: SubjectContext = { sub: this.pendingStep.sub }
    const stepSub = this.pendingStep.sub
    let nextStep: NextStep | null = null
    if (this.options.onStepSubmitted !== undefined) {
      try {
        const result = await this.options.onStepSubmitted(stepData, stepContext)
        if (result !== null && result !== undefined && typeof result === 'object') {
          nextStep = result
        }
      } catch {
        jsonResponse(res, 500, {
          error: 'server_error',
          error_description: 'Failed to process step input'
        })
        return
      }
    }

    if (nextStep !== null && nextStep.type === 'error') {
      const errText = typeof nextStep.text === 'string' ? nextStep.text : 'Invalid input'
      jsonResponse(res, 200, { ok: false, error: errText })
      return
    }

    if (nextStep !== null && (nextStep.type === 'otp_required' || nextStep.type === 'password_required')) {
      this.markPendingStep(stepSub)
      jsonResponse(res, 200, { ok: true, next_step: nextStep })
      return
    }

    try {
      await markConfigSetupComplete(this.options.serverName)
    } catch (err) {
      console.warn(
        'Failed to mark _setup_complete=true for %s: %s',
        this.options.serverName,
        err instanceof Error ? err.message : String(err)
      )
    }
    this.clearPendingStep()
    jsonResponse(res, 200, { ok: true })
  }

  async setupStatusHandler(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    jsonResponse(res, 200, this.setupStatus)
  }

  async wellKnownAs(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const base = getBaseUrl(req)
    jsonResponse(res, 200, authorizationServerMetadata(base))
  }

  async wellKnownPr(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const base = getBaseUrl(req)
    jsonResponse(res, 200, protectedResourceMetadata(base, [base]))
  }

  async registerHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let body: Record<string, unknown> = {}
    try {
      const raw = await parseJsonBody(req)
      body = raw as Record<string, unknown>
    } catch {
      // fall through
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

  markSetupComplete(key = 'gdrive'): void {
    this.setupStatus[key] = 'complete'
  }

  markSetupFailed(key = 'gdrive', error = 'unknown error'): void {
    const collapsed = String(error).replace(/\s+/g, ' ').trim()
    const message = collapsed.length > 0 ? collapsed : 'unknown error'
    this.setupStatus[key] = `error:${message}`
  }

  async rootHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
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

  async callbackDoneHandler(_req: IncomingMessage, res: ServerResponse): Promise<void> {
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

  private parseCookies(req: IncomingMessage): Record<string, string> {
    const header = req.headers.cookie
    if (!header) return {}
    const out: Record<string, string> = {}
    for (const part of header.split(';')) {
      const idx = part.indexOf('=')
      if (idx < 0) continue
      const k = part.slice(0, idx).trim()
      const v = part.slice(idx + 1).trim()
      if (k.length > 0) out[k] = decodeURIComponent(v)
    }
    return out
  }

  private clientIp(req: IncomingMessage): string {
    const fwd = req.headers['x-forwarded-for']
    if (typeof fwd === 'string' && fwd.length > 0) {
      return fwd.split(',')[0].trim()
    }
    return req.socket.remoteAddress ?? 'unknown'
  }

  private buildResAdapter(res: ServerResponse): {
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

  private withRelayGate(inner: RequestHandler): RequestHandler {
    return async (req, res) => {
      if (!this.relayPassword) {
        await inner(req, res)
        return
      }
      const cookies = this.parseCookies(req)
      const expressReq = {
        cookies,
        originalUrl: req.url ?? '/'
      }
      const { adapter, isComplete } = this.buildResAdapter(res)
      let proceed = false
      await this.relayMw(expressReq as never, adapter as never, () => {
        proceed = true
      })
      if (proceed && !isComplete()) {
        await inner(req, res)
      }
    }
  }

  private async loginGetRoute(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const expressReq = { query: { next: url.searchParams.get('next') ?? '/authorize' } }
    const { adapter } = this.buildResAdapter(res)
    await loginGetHandler(expressReq as never, adapter as never)
  }

  private async loginPostRoute(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let body: Record<string, string> = {}
    try {
      body = await parseFormBody(req)
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'invalid_request' }))
      return
    }
    const expressReq = { body, ip: this.clientIp(req) }
    const { adapter } = this.buildResAdapter(res)
    await loginPostHandler(expressReq as never, adapter as never)
  }

  getHandler(): RequestHandler {
    return createRouter([
      { method: 'GET', path: '/', handler: this.rootHandler.bind(this) },
      { method: 'GET', path: '/login', handler: this.loginGetRoute.bind(this) },
      { method: 'POST', path: '/login', handler: this.loginPostRoute.bind(this) },
      { method: 'GET', path: '/authorize', handler: this.withRelayGate(this.authorizeGet.bind(this)) },
      { method: 'POST', path: '/authorize', handler: this.withRelayGate(this.authorizePost.bind(this)) },
      { method: 'POST', path: '/authorize/prefill', handler: this.withRelayGate(this.authorizePrefill.bind(this)) },
      { method: 'POST', path: '/token', handler: this.token.bind(this) },
      { method: 'POST', path: '/register', handler: this.registerHandler.bind(this) },
      { method: 'POST', path: '/otp', handler: this.otpHandler.bind(this) },
      { method: 'GET', path: '/setup-status', handler: this.setupStatusHandler.bind(this) },
      { method: 'GET', path: '/callback-done', handler: this.callbackDoneHandler.bind(this) },
      { method: 'GET', path: '/.well-known/oauth-authorization-server', handler: this.wellKnownAs.bind(this) },
      { method: 'GET', path: '/.well-known/oauth-protected-resource', handler: this.wellKnownPr.bind(this) }
    ])
  }
}

/**
 * Create OAuth 2.1 Authorization Server HTTP handler.
 *
 * Returns a handler compatible with ``http.createServer`` along with the
 * ``JWTIssuer`` (for the transport layer to verify Bearer tokens) and a
 * ``markSetupComplete`` function for background setup callbacks (e.g. GDrive
 * device code flow).
 */
export async function createLocalOAuthApp(options: LocalOAuthAppOptions): Promise<LocalOAuthAppResult> {
  const server = new LocalOAuthServer(options)
  await server.init()

  return {
    handler: server.getHandler(),
    jwtIssuer: server.jwtIssuer,
    markSetupComplete: server.markSetupComplete.bind(server),
    markSetupFailed: server.markSetupFailed.bind(server)
  }
}

// ---------------------------------------------------------------------------
// D7 — Pre-fill renderer + form-submission merger.
//
// These helpers mirror the core-py exports of the same names. They are
// intentionally NOT wired into the default ``authorizeGet`` / ``authorizePost``
// above — that path stays on ``renderCredentialForm`` for legacy parity. New
// consumers (transparent-bridge Wave 1) compose ``renderField`` per field for
// secret-aware rendering, then call ``mergeSubmission`` to merge the POST body
// with their stored ``config.enc`` so a missing secret in the body preserves
// the previously stored value instead of clearing it.
// ---------------------------------------------------------------------------

const SECRET_PLACEHOLDER = '••••••••(configured)'

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/**
 * Resolve the canonical config key for a relay field.
 *
 * Two schema styles coexist in the codebase: D7 ``RelayConfigField`` uses
 * ``name``; legacy ``ConfigField`` (consumed by ``renderCredentialForm``)
 * uses ``key``. ``renderField`` and ``mergeSubmission`` accept both so a
 * consumer can mix or migrate without rewriting field dicts. ``name`` wins
 * when both are present.
 */
function fieldName(field: RelayConfigField | Record<string, unknown>): string {
  const raw = field as Record<string, unknown>
  const name = typeof raw.name === 'string' ? raw.name : ''
  if (name.length > 0) return name
  const key = typeof raw.key === 'string' ? raw.key : ''
  return key
}

/**
 * Render an HTML ``<label>+<input>`` for a single relay field.
 *
 * Rules per D7:
 *  - oauth_field: render Re-authorize button (no plaintext exposed)
 *  - secret + value present: placeholder, empty input, "Replace" checkbox
 *  - secret + no value: empty input with field label as placeholder
 *  - non-secret: pre-fill with ``currentValue`` as input ``value`` attr
 */
export function renderField(field: RelayConfigField, currentValue: unknown): string {
  const name = fieldName(field)
  const label = field.label ?? name
  const fieldType = field.type ?? 'text'

  if (isOAuthField(field)) {
    const status = currentValue ? 'Connected' : 'Not connected'
    return (
      `<div class="field oauth-field"><label>${escapeHtml(label)}</label> ` +
      `<span class="oauth-status">${status}</span> ` +
      `<button type="button" class="oauth-reauth" data-field="${escapeHtml(name)}">` +
      `Re-authorize</button></div>`
    )
  }

  if (isSecretField(field)) {
    if (currentValue) {
      return (
        `<div class="field secret-field"><label for="field-${escapeHtml(name)}">${escapeHtml(label)}</label> ` +
        `<input id="field-${escapeHtml(name)}" type="password" name="${escapeHtml(name)}" value="" ` +
        `placeholder="${escapeHtml(SECRET_PLACEHOLDER)}" ` +
        `data-secret-configured="true"> ` +
        `<label for="replace-${escapeHtml(name)}" class="replace-toggle"><input id="replace-${escapeHtml(name)}" type="checkbox" ` +
        `name="__replace_${escapeHtml(name)}" value="1"> Replace this credential</label>` +
        `</div>`
      )
    }
    return (
      `<div class="field secret-field"><label for="field-${escapeHtml(name)}">${escapeHtml(label)}</label> ` +
      `<input id="field-${escapeHtml(name)}" type="password" name="${escapeHtml(name)}" value="" ` +
      `placeholder="${escapeHtml(label)}"></div>`
    )
  }

  const valueAttr = currentValue !== null && currentValue !== undefined ? escapeHtml(String(currentValue)) : ''
  return (
    `<div class="field"><label for="field-${escapeHtml(name)}">${escapeHtml(label)}</label> ` +
    `<input id="field-${escapeHtml(name)}" type="${escapeHtml(fieldType)}" name="${escapeHtml(name)}" ` +
    `value="${valueAttr}"></div>`
  )
}

/**
 * Merge a form submission into the current config per D7 rules.
 *
 * Behavior:
 *  - Empty secret -> preserve the existing value (avoid clearing on a
 *    re-submit where the user did not retype the credential).
 *  - Non-empty secret -> replace.
 *  - Non-secret -> always replace (including with an empty string, so the
 *    user can intentionally blank a field).
 *  - oauth_field -> ignored here; OAuth fields are managed by their own
 *    Re-authorize flow, never by raw form input.
 */
export function mergeSubmission(
  current: Record<string, unknown>,
  submitted: Record<string, unknown>,
  schemaFields: RelayConfigField[]
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...current }
  for (const field of schemaFields) {
    const name = fieldName(field)
    if (!name) continue
    if (isOAuthField(field)) continue
    const newValue = submitted[name] ?? ''
    if (isSecretField(field)) {
      if (newValue === '' || newValue === null || newValue === undefined) {
        continue
      }
      result[name] = newValue
    } else {
      result[name] = newValue
    }
  }
  return result
}
