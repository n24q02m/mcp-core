/**
 * Local OAuth 2.1 Authorization Server as an HTTP request handler.
 *
 * Provides a self-hosted Authorization Server for single-user MCP servers.
 * Implements the OAuth 2.1 PKCE flow with credential collection via a
 * browser-rendered form.
 *
 * Routes:
 * - GET  /                                         -- Auto-bootstrap PKCE then redirect to /authorize
 * - GET  /authorize                                -- Render credential form
 * - POST /authorize                                -- Save credentials, return auth code
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
  if (computed.length !== codeChallenge.length) return false
  try {
    return timingSafeEqual(Buffer.from(computed, 'ascii'), Buffer.from(codeChallenge, 'ascii'))
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

function parseCookies(req: IncomingMessage): Record<string, string> {
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

function clientIp(req: IncomingMessage): string {
  const fwd = req.headers['x-forwarded-for']
  if (typeof fwd === 'string' && fwd.length > 0) {
    return fwd.split(',')[0].trim()
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

class LocalOAuthApp {
  private readonly pendingSessions = new Map<string, PendingSession>()
  private readonly authCodes = new Map<string, AuthCodeEntry>()
  private readonly pendingPrefills = new Map<string, { data: Record<string, string>; createdAt: number }>()
  private readonly PREFILL_TTL_S = 300
  private pendingStep: PendingStep | null = null
  private readonly setupStatus: Record<string, string> = { gdrive: 'idle' }
  private readonly relayPassword = process.env.MCP_RELAY_PASSWORD ?? ''
  private readonly relayMw = createRelayLoginMiddleware({ password: this.relayPassword })

  constructor(
    private readonly options: LocalOAuthAppOptions,
    public readonly jwtIssuer: JWTIssuer
  ) {
    configureRelayLogin(this.relayPassword)
  }

  markSetupComplete(key = 'gdrive'): void {
    this.setupStatus[key] = 'complete'
  }

  markSetupFailed(key = 'gdrive', error = 'unknown error'): void {
    const collapsed = String(error).split(/\s+/).filter(Boolean).join(' ')
    const message = collapsed.length > 0 ? collapsed : 'unknown error'
    this.setupStatus[key] = `error:${message}`
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
    if (this.pendingPrefills.has(state)) {
      const entry = this.pendingPrefills.get(state)!
      Object.assign(prefill, entry.data)
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
        error_description: 'Invalid JSON body'
      })
      return
    }

    for (const key of Object.keys(this.setupStatus)) {
      this.setupStatus[key] = 'idle'
    }

    let nextStep: NextStep | null = null
    if (this.options.onCredentialsSaved !== undefined) {
      try {
        const result = await this.options.onCredentialsSaved(credentials, { sub: session.sub })
        if (result !== null && result !== undefined && typeof result === 'object') {
          nextStep = result
        }
      } catch {
        jsonResponse(res, 500, {
          error: 'server_error',
          error_description: 'Failed to save credentials'
        })
        return
      }
    }

    const isMultiStep = nextStep !== null && (nextStep.type === 'otp_required' || nextStep.type === 'password_required')
    if (!isMultiStep) {
      try {
        await markConfigSetupComplete(this.options.serverName)
      } catch (err) {
        console.warn(
          `Failed to mark _setup_complete=true for ${this.options.serverName}:`,
          err instanceof Error ? err.message : String(err)
        )
      }
    }

    const authCode = randomBytes(32).toString('base64url')
    this.authCodes.set(authCode, {
      codeChallenge: session.codeChallenge,
      codeChallengeMethod: session.codeChallengeMethod,
      createdAt: Date.now(),
      sub: session.sub
    })
    pruneExpired(this.authCodes, AUTH_CODE_TTL_S * 1000)

    const separator = session.redirectUri.includes('?') ? '&' : '?'
    const redirectUrl = `${session.redirectUri}${separator}code=${authCode}&state=${session.state}`

    const body: Record<string, unknown> = { ok: true, redirect_url: redirectUrl }
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

  async token(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let form: Record<string, string>
    try {
      form = await parseFormBody(req)
    } catch {
      jsonResponse(res, 400, { error: 'invalid_request' })
      return
    }

    const grantType = form.grant_type
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

    const accessToken = await this.jwtIssuer.issueAccessToken(entry.sub)
    jsonResponse(res, 200, {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600
    })
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

    let body: Record<string, string>
    try {
      body = await parseJsonBody<Record<string, string>>(req)
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

    const stepSub = this.pendingStep.sub

    let nextStep: NextStep | null = null
    if (this.options.onStepSubmitted !== undefined) {
      try {
        const result = await this.options.onStepSubmitted(body, { sub: stepSub })
        if (result !== null && result !== undefined && typeof result === 'object') {
          nextStep = result
        }
      } catch {
        this.clearPendingStep()
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

    this.clearPendingStep()

    if (nextStep !== null && (nextStep.type === 'otp_required' || nextStep.type === 'password_required')) {
      this.markPendingStep(stepSub)
      jsonResponse(res, 200, { ok: true, next_step: nextStep })
      return
    }

    try {
      await markConfigSetupComplete(this.options.serverName)
    } catch (err) {
      console.warn(
        `Failed to mark _setup_complete=true for ${this.options.serverName}:`,
        err instanceof Error ? err.message : String(err)
      )
    }
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

  withRelayGate(inner: RequestHandler): RequestHandler {
    return async (req, res) => {
      if (!this.relayPassword) {
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
      await this.relayMw(expressReq as never, adapter as never, () => {
        proceed = true
      })
      if (proceed && !isComplete()) {
        await inner(req, res)
      }
    }
  }

  async loginGetRoute(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const expressReq = { query: { next: url.searchParams.get('next') ?? '/authorize' } }
    const { adapter } = buildResAdapter(res)
    await loginGetHandler(expressReq as never, adapter as never)
  }

  async loginPostRoute(req: IncomingMessage, res: ServerResponse): Promise<void> {
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
}

export async function createLocalOAuthApp(options: LocalOAuthAppOptions): Promise<LocalOAuthAppResult> {
  const jwtIssuer = options.jwtIssuer ?? new JWTIssuer(options.serverName)
  await jwtIssuer.init()

  const app = new LocalOAuthApp(options, jwtIssuer)

  const handler = createRouter([
    { method: 'GET', path: '/', handler: (req, res) => app.rootHandler(req, res) },
    { method: 'GET', path: '/login', handler: (req, res) => app.loginGetRoute(req, res) },
    { method: 'POST', path: '/login', handler: (req, res) => app.loginPostRoute(req, res) },
    { method: 'GET', path: '/authorize', handler: app.withRelayGate((req, res) => app.authorize(req, res)) },
    { method: 'POST', path: '/authorize', handler: app.withRelayGate((req, res) => app.authorize(req, res)) },
    {
      method: 'POST',
      path: '/authorize/prefill',
      handler: app.withRelayGate((req, res) => app.authorizePrefill(req, res))
    },
    { method: 'POST', path: '/token', handler: (req, res) => app.token(req, res) },
    { method: 'POST', path: '/register', handler: (req, res) => app.registerHandler(req, res) },
    { method: 'POST', path: '/otp', handler: (req, res) => app.otpHandler(req, res) },
    { method: 'GET', path: '/setup-status', handler: (req, res) => app.setupStatusHandler(req, res) },
    { method: 'GET', path: '/callback-done', handler: (req, res) => app.callbackDoneHandler(req, res) },
    {
      method: 'GET',
      path: '/.well-known/oauth-authorization-server',
      handler: (req, res) => app.wellKnownAs(req, res)
    },
    { method: 'GET', path: '/.well-known/oauth-protected-resource', handler: (req, res) => app.wellKnownPr(req, res) }
  ])

  return {
    handler,
    jwtIssuer,
    markSetupComplete: (key) => app.markSetupComplete(key),
    markSetupFailed: (key, error) => app.markSetupFailed(key, error)
  }
}

// ---------------------------------------------------------------------------
// D7 — Pre-fill renderer + form-submission merger.
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

function fieldName(field: RelayConfigField | Record<string, unknown>): string {
  const raw = field as Record<string, unknown>
  const name = typeof raw.name === 'string' ? raw.name : ''
  if (name.length > 0) return name
  const key = typeof raw.key === 'string' ? raw.key : ''
  return key
}

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
        `<div class="field secret-field"><label>${escapeHtml(label)}</label> ` +
        `<input type="password" name="${escapeHtml(name)}" value="" ` +
        `placeholder="${escapeHtml(SECRET_PLACEHOLDER)}" ` +
        `data-secret-configured="true"> ` +
        `<label class="replace-toggle"><input type="checkbox" ` +
        `name="__replace_${escapeHtml(name)}" value="1"> Replace this credential</label>` +
        `</div>`
      )
    }
    return (
      `<div class="field secret-field"><label>${escapeHtml(label)}</label> ` +
      `<input type="password" name="${escapeHtml(name)}" value="" ` +
      `placeholder="${escapeHtml(label)}"></div>`
    )
  }

  const valueAttr = currentValue !== null && currentValue !== undefined ? escapeHtml(String(currentValue)) : ''
  return (
    `<div class="field"><label>${escapeHtml(label)}</label> ` +
    `<input type="${escapeHtml(fieldType)}" name="${escapeHtml(name)}" ` +
    `value="${valueAttr}"></div>`
  )
}

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
