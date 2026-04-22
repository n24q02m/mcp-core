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
import { type RelayConfigSchema, renderCredentialForm } from './credential-form.js'
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
   * ``submitUrl`` (which embeds the PKCE nonce) and returns the full HTML
   * page. Consumers (email, telegram) use this to inject rich UX while
   * reusing core OAuth plumbing.
   */
  customCredentialFormHtml?: (schema: RelayConfigSchema, options: { submitUrl: string }) => string
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
 * Create OAuth 2.1 Authorization Server HTTP handler.
 *
 * Returns a handler compatible with ``http.createServer`` along with the
 * ``JWTIssuer`` (for the transport layer to verify Bearer tokens) and a
 * ``markSetupComplete`` function for background setup callbacks (e.g. GDrive
 * device code flow).
 */
export async function createLocalOAuthApp(options: LocalOAuthAppOptions): Promise<LocalOAuthAppResult> {
  const jwtIssuer = options.jwtIssuer ?? new JWTIssuer(options.serverName)
  await jwtIssuer.init()

  // In-memory stores keyed by nonce / auth_code. Each entry has a ``createdAt``
  // for TTL expiry.
  const pendingSessions = new Map<string, PendingSession>()
  const authCodes = new Map<string, AuthCodeEntry>()

  // Single-user local mode: one pending multi-step session at a time.
  let pendingStep: PendingStep | null = null
  const setupStatus: Record<string, string> = { gdrive: 'idle' }

  function markPendingStep(sub: string): void {
    pendingStep = { active: true, createdAt: Date.now(), attempts: 0, sub }
  }

  function clearPendingStep(): void {
    pendingStep = null
  }

  // ------------------------------------------------------------------
  // Route handlers
  // ------------------------------------------------------------------

  async function authorizeGet(req: IncomingMessage, res: ServerResponse): Promise<void> {
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

    const nonce = randomBytes(32).toString('base64url')
    // Generate a per-authorize-request subject here (not at /token time) so the
    // credential save callback and the eventual JWT share the same ``sub``. If
    // this were derived at /token, concurrent authorize requests would collide
    // on a static 'local-user' subject and leak credentials across users.
    const sub = randomBytes(16).toString('base64url')
    pendingSessions.set(nonce, {
      clientId,
      redirectUri,
      state,
      codeChallenge,
      codeChallengeMethod,
      createdAt: Date.now(),
      sub
    })
    pruneExpired(pendingSessions, SESSION_TTL_S * 1000)

    const base = getBaseUrl(req)
    const submitUrl = `${base}/authorize?nonce=${nonce}`
    const html =
      options.customCredentialFormHtml !== undefined
        ? options.customCredentialFormHtml(options.relaySchema, { submitUrl })
        : renderCredentialForm(options.relaySchema, { submitUrl })
    htmlResponse(res, 200, html)
  }

  async function authorizePost(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const nonce = url.searchParams.get('nonce')
    if (!nonce || !pendingSessions.has(nonce)) {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Invalid or expired nonce'
      })
      return
    }

    const session = pendingSessions.get(nonce) as PendingSession
    pendingSessions.delete(nonce)

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

    // Save credentials via callback. Callback may return a dict with
    // next_step info (e.g. GDrive OAuth device code to show in the form).
    // The per-authorize ``sub`` is threaded through so consumers persist
    // credentials keyed by subject — subsequently the JWT issued at /token
    // will carry this same sub, letting tool handlers load the correct
    // credential set via AsyncLocalStorage.
    let nextStep: NextStep | null = null
    if (options.onCredentialsSaved !== undefined) {
      try {
        const result = await options.onCredentialsSaved(credentials, { sub: session.sub })
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

    // Generate auth code. Carry ``sub`` so /token can issue JWT with the
    // same subject the credentials were saved under.
    const authCode = randomBytes(32).toString('base64url')
    authCodes.set(authCode, {
      codeChallenge: session.codeChallenge,
      codeChallengeMethod: session.codeChallengeMethod,
      createdAt: Date.now(),
      sub: session.sub
    })
    pruneExpired(authCodes, AUTH_CODE_TTL_S * 1000)

    const separator = session.redirectUri.includes('?') ? '&' : '?'
    const redirectUrl = `${session.redirectUri}${separator}code=${authCode}&state=${session.state}`

    const body: Record<string, unknown> = { ok: true, redirect_url: redirectUrl }
    if (nextStep !== null) {
      body.next_step = nextStep
      // If next_step requires additional input (OTP or 2FA password),
      // activate pending step session so /otp endpoint accepts input.
      // Capture the authorize-session sub so /otp can thread the correct
      // SubjectContext into onStepSubmitted (the browser POSTs to /otp
      // with step data only — no sub in body).
      const stepType = nextStep.type
      if (stepType === 'otp_required' || stepType === 'password_required') {
        markPendingStep(session.sub)
      }
    }
    jsonResponse(res, 200, body)
  }

  async function authorize(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === 'GET') {
      await authorizeGet(req, res)
      return
    }
    await authorizePost(req, res)
  }

  async function token(req: IncomingMessage, res: ServerResponse): Promise<void> {
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

    const entry = authCodes.get(code)
    if (entry === undefined) {
      jsonResponse(res, 400, { error: 'invalid_grant' })
      return
    }
    authCodes.delete(code)

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

    // Issue JWT with the subject bound to this authorize session. Historically
    // this was the static string 'local-user' — that collapsed every concurrent
    // browser into one subject and made credential isolation impossible. The
    // new flow mints a fresh UUID in authorizeGet (PendingSession.sub), carries
    // it through onCredentialsSaved, and issues it here so the Bearer returned
    // to the client scopes future /mcp calls to this user's credentials.
    const accessToken = await jwtIssuer.issueAccessToken(entry.sub)
    jsonResponse(res, 200, {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600
    })
  }

  async function otpHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // 1. Active session check.
    if (pendingStep === null || !pendingStep.active) {
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'No active step session'
      })
      return
    }

    // 2. Timeout check.
    if (Date.now() - pendingStep.createdAt > OTP_TIMEOUT_S * 1000) {
      clearPendingStep()
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Step session expired'
      })
      return
    }

    // 3. Parse JSON body BEFORE incrementing attempts. Malformed input
    // must not consume the user's retry quota nor clear the session.
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

    // 4. Increment attempts counter (count every valid-JSON submit).
    pendingStep.attempts += 1

    // 5. Attempt limit check.
    if (pendingStep.attempts > OTP_MAX_ATTEMPTS) {
      clearPendingStep()
      jsonResponse(res, 400, {
        error: 'invalid_request',
        error_description: 'Too many attempts'
      })
      return
    }

    // 6. Dispatch to step callback with the authorize-session sub so
    // consumers (telegram Telethon multi-user) can route to the correct
    // per-user state.
    const stepContext: SubjectContext = { sub: pendingStep.sub }
    const stepSub = pendingStep.sub
    let nextStep: NextStep | null = null
    if (options.onStepSubmitted !== undefined) {
      try {
        const result = await options.onStepSubmitted(stepData, stepContext)
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

    // Error from callback: keep pending session, allow retry.
    if (nextStep !== null && nextStep.type === 'error') {
      const errText = typeof nextStep.text === 'string' ? nextStep.text : 'Invalid input'
      jsonResponse(res, 200, { ok: false, error: errText })
      return
    }

    // Chain to next step: reset counters so the new step gets its own quota.
    // Preserve the original sub so the whole multi-step chain belongs to the
    // same user.
    if (nextStep !== null && (nextStep.type === 'otp_required' || nextStep.type === 'password_required')) {
      markPendingStep(stepSub)
      jsonResponse(res, 200, { ok: true, next_step: nextStep })
      return
    }

    // Completion (callback returned null / undefined or unknown dict type).
    clearPendingStep()
    jsonResponse(res, 200, { ok: true })
  }

  async function setupStatusHandler(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    jsonResponse(res, 200, setupStatus)
  }

  async function wellKnownAs(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const base = getBaseUrl(req)
    jsonResponse(res, 200, authorizationServerMetadata(base))
  }

  async function wellKnownPr(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const base = getBaseUrl(req)
    jsonResponse(res, 200, protectedResourceMetadata(base, [base]))
  }

  /**
   * RFC 7591 Dynamic Client Registration.
   *
   * Local OAuth server uses a fixed public client id (`local-browser`).
   * DCR is echo-style — mirror the client's submitted metadata back with
   * the fixed id so MCP clients (Python SDK OAuthClientProvider, etc.)
   * can bootstrap OAuth without failing at the registration step.
   */
  async function registerHandler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let body: Record<string, unknown> = {}
    try {
      const raw = await parseJsonBody(req)
      body = raw as Record<string, unknown>
    } catch {
      // fall through with empty body
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

  function markSetupComplete(key = 'gdrive'): void {
    setupStatus[key] = 'complete'
  }

  /**
   * Mark a background setup step as failed. The status becomes
   * ``"error:<message>"`` so the frontend poll handler can surface the
   * message and stop spinning. Whitespace is collapsed to keep the value
   * single-line (the frontend inlines it verbatim).
   */
  function markSetupFailed(key = 'gdrive', error = 'unknown error'): void {
    const collapsed = String(error).split(/\s+/).filter(Boolean).join(' ')
    const message = collapsed.length > 0 ? collapsed : 'unknown error'
    setupStatus[key] = `error:${message}`
  }

  /**
   * GET / -- auto-generate PKCE and redirect to /authorize.
   *
   * The ``/authorize`` endpoint requires 4 PKCE parameters; users arriving
   * from a log line / bookmark have no way to construct them. Bootstrap a
   * default ``local-browser`` client here: generate random state + S256
   * challenge, redirect to ``/authorize``, and on success return to
   * ``/callback-done`` for a friendly close message. Keeps the one-URL UX
   * ("open http://... in browser") working without exposing the raw OAuth
   * machinery to end users.
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
   *
   * Users redirected from the bootstrap flow land here on success. Exists
   * purely so the bare URL doesn't 404 after the PKCE redirect completes.
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

  const handler = createRouter([
    { method: 'GET', path: '/', handler: rootHandler },
    { method: 'GET', path: '/authorize', handler: authorize },
    { method: 'POST', path: '/authorize', handler: authorize },
    { method: 'POST', path: '/token', handler: token },
    { method: 'POST', path: '/register', handler: registerHandler },
    { method: 'POST', path: '/otp', handler: otpHandler },
    { method: 'GET', path: '/setup-status', handler: setupStatusHandler },
    { method: 'GET', path: '/callback-done', handler: callbackDoneHandler },
    { method: 'GET', path: '/.well-known/oauth-authorization-server', handler: wellKnownAs },
    { method: 'GET', path: '/.well-known/oauth-protected-resource', handler: wellKnownPr }
  ])

  return { handler, jwtIssuer, markSetupComplete, markSetupFailed }
}
