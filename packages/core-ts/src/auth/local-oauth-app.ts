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
      ? // ⚡ Bolt: Avoid array allocation in header parsing
        (forwardedProto.indexOf(',') !== -1
          ? forwardedProto.substring(0, forwardedProto.indexOf(','))
          : forwardedProto
        ).trim()
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
  const jwtIssuer =
    options.jwtIssuer ?? new JWTIssuer(options.serverName, undefined, process.env.CREDENTIAL_SECRET ?? null)
  await jwtIssuer.init()

  // In-memory stores keyed by nonce / auth_code. Each entry has a ``createdAt``
  // for TTL expiry.
  const pendingSessions = new Map<string, PendingSession>()
  const authCodes = new Map<string, AuthCodeEntry>()

  // Server-side prefill keyed by OAuth ``state`` (the PKCE state token chosen
  // by the client BEFORE the GET /authorize redirect). The E2E driver POSTs
  // skret-derived form values here so the URL it announces to the user does
  // NOT contain credential bytes. Without this, ``?prefill_TELEGRAM_PHONE=
  // %2B84...`` would land in browser history, server access logs, screenshots
  // and HTTP referrer headers — every place a URL leaks.
  const pendingPrefills = new Map<string, { data: Record<string, string>; createdAt: number }>()
  const PREFILL_TTL_S = 300

  // Single-user local mode: one pending multi-step session at a time.
  let pendingStep: PendingStep | null = null
  const setupStatus: Record<string, string> = { gdrive: 'idle' }

  // Edge auth password gate. When ``MCP_RELAY_PASSWORD`` is set, /authorize
  // GET + POST + /authorize/prefill are fronted by a cookie-session
  // middleware. Empty password disables the gate (single-user dev). See
  // spec ``2026-05-01-stdio-pure-http-multiuser §4.2.1``. Configured here
  // (not module-scope) so multi-app test setups don't leak state across
  // apps; the relay-login module itself keeps a single shared password
  // string, intentional because in deploy each container hosts one app.
  const relayPassword = process.env.MCP_RELAY_PASSWORD ?? ''
  configureRelayLogin(relayPassword)
  const relayMw = createRelayLoginMiddleware({ password: relayPassword })

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

    // Resolve prefill values for the form. Two channels, in priority order:
    //  1. Server-side store keyed by ``state`` — written by the E2E driver
    //     via POST /authorize/prefill BEFORE the user opens the URL. This is
    //     the safe channel; nothing leaves the server boundary.
    //  2. URL query string ``?prefill_<KEY>=<VALUE>`` — legacy fallback for
    //     callers that have not migrated yet. Deprecated; emitted to
    //     ``X-Prefill-Source: url`` so callers can find them via access logs.
    // Renderers receive the flat ``{KEY: VALUE}`` map and emit ``value="..."``
    // on matching inputs.
    const prefill: Record<string, string> = {}
    pruneExpired(pendingPrefills, PREFILL_TTL_S * 1000)
    const stored = pendingPrefills.get(state)
    if (stored) {
      // Explicit per-key copy (not Object.assign / spread) — values landed
      // here via authorizePrefill which coerces every value through String()
      // and rejects empty strings, but we restate the contract here so static
      // analyzers don't flag the merge as a mass-assignment sink.
      // nosemgrep: javascript.express.security.express-data-exfiltration.express-data-exfiltration
      for (const [k, v] of Object.entries(stored.data)) {
        prefill[k] = String(v)
      }
      pendingPrefills.delete(state)
    } else {
      params.forEach((value, key) => {
        if (key.startsWith('prefill_')) {
          prefill[key.slice('prefill_'.length)] = value
        }
      })
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
        ? options.customCredentialFormHtml(options.relaySchema, { submitUrl, prefill })
        : renderCredentialForm(options.relaySchema, { submitUrl, prefill })
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

    // Reset stale completion markers from previous authorize submits.
    // setupStatus is module-scoped, so a key flipped to "complete" by a
    // prior background poll (e.g. Outlook device code finished on the
    // first attempt) would otherwise persist into the next form submit.
    // The frontend renders a fresh oauth_device_code UI and starts
    // polling /setup-status, which returns the stale "complete" within
    // a few seconds and triggers a premature redirect — the user sees
    // the device code flash on screen and then the "setup complete"
    // banner before they ever open microsoft.com/link. Reset all keys
    // back to "idle" here so each submit starts from a clean state.
    for (const key of Object.keys(setupStatus)) {
      setupStatus[key] = 'idle'
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

    // Mark the persistent ``_setup_complete`` flag once the user submits
    // successfully. Multi-step flows (OTP / 2FA) defer marking until the
    // final step in ``otpHandler`` — see core-py parity. Best-effort: any
    // storage error is logged via warning rather than failing the response.
    const isMultiStep = nextStep !== null && (nextStep.type === 'otp_required' || nextStep.type === 'password_required')
    if (!isMultiStep) {
      try {
        await markConfigSetupComplete(options.serverName)
      } catch (err) {
        console.warn(
          'Failed to mark _setup_complete=true for %s: %s',
          options.serverName,
          err instanceof Error ? err.message : String(err)
        )
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

  async function authorizePrefill(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Driver-only side-channel: store form prefill values keyed by the OAuth
    // ``state`` token chosen by the client. ``GET /authorize?state=<X>`` then
    // hydrates the form on render — credentials never appear in the URL.
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
    // Coerce all values to string + drop empties so blank ``value=""`` attrs
    // don't shadow the placeholder text in the rendered form.
    const data: Record<string, string> = {}
    for (const [k, v] of Object.entries(body)) {
      if (v != null && String(v).length > 0) {
        data[k] = String(v)
      }
    }
    pendingPrefills.set(state, { data, createdAt: Date.now() })
    pruneExpired(pendingPrefills, PREFILL_TTL_S * 1000)
    jsonResponse(res, 204, {})
  }

  /**
   * Build and write the standard /token success body for ``sub``.
   *
   * Issues a fresh access token AND a fresh refresh token. The refresh token
   * lets long-running MCP clients renew the 1h access token without re-running
   * the browser PKCE flow (issue #261). ``scope`` advertises ``offline_access``
   * so clients know a refresh token was granted.
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
   * expires on its own 30-day clock; clients replace it with the rotated one.
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

    const grantType = form.grant_type
    if (grantType === 'refresh_token') {
      await handleRefreshToken(res, form)
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
    await issueTokenResponse(res, entry.sub)
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
    // Mark persistent _setup_complete flag now that the multi-step chain has
    // finished — single-step counterpart lives in authorizePost.
    try {
      await markConfigSetupComplete(options.serverName)
    } catch (err) {
      console.warn(
        'Failed to mark _setup_complete=true for %s: %s',
        options.serverName,
        err instanceof Error ? err.message : String(err)
      )
    }
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

  async function wellKnownJwks(_req: IncomingMessage, res: ServerResponse): Promise<void> {
    jsonResponse(res, 200, await jwtIssuer.getJwks())
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
    // ⚡ Bolt: Replace multiple array allocations (.split.filter.join) with regex replace for faster whitespace collapsing
    const collapsed = String(error).replace(/\s+/g, ' ').trim()
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

  // ------------------------------------------------------------------
  // Relay password gate adapters.
  //
  // The relay-login module exposes Express-style handlers (``req.body``,
  // ``res.status().send()`` etc) so the same logic can be unit-tested
  // without a live HTTP server. Here we adapt them onto the project's
  // ``IncomingMessage`` / ``ServerResponse`` router. Each adapter:
  //   1. Parses ``Cookie`` into ``req.cookies``,
  //   2. Mounts ``res.status / res.send / res.cookie / res.redirect /
  //      res.header / res.set`` on top of ``res.writeHead`` / ``res.end``,
  //   3. Lets the relay-login handler do the work.
  //
  // Only ``/authorize`` GET + POST + ``/authorize/prefill`` go through
  // ``relayMw``; ``/token``, ``/register``, ``/otp``, ``/setup-status``,
  // ``/.well-known/*``, ``/`` and ``/callback-done`` are intentionally NOT
  // gated — they're machine endpoints (DCR / token exchange / metadata) or
  // auto-bootstrap helpers that must remain accessible without the cookie.
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
      // ⚡ Bolt: Avoid array allocation in header parsing
      return (fwd.indexOf(',') !== -1 ? fwd.substring(0, fwd.indexOf(',')) : fwd).trim()
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
          // Capitalise SameSite values (lax → Lax, strict → Strict).
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

  /**
   * Adapter: bind ``loginGetHandler`` / ``loginPostHandler`` (Express-style)
   * onto IncomingMessage / ServerResponse routes.
   */
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

  const handler = createRouter([
    { method: 'GET', path: '/', handler: rootHandler },
    { method: 'GET', path: '/login', handler: loginGetRoute },
    { method: 'POST', path: '/login', handler: loginPostRoute },
    { method: 'GET', path: '/authorize', handler: withRelayGate(authorize) },
    { method: 'POST', path: '/authorize', handler: withRelayGate(authorize) },
    { method: 'POST', path: '/authorize/prefill', handler: withRelayGate(authorizePrefill) },
    { method: 'POST', path: '/token', handler: token },
    { method: 'POST', path: '/register', handler: registerHandler },
    { method: 'POST', path: '/otp', handler: otpHandler },
    { method: 'GET', path: '/setup-status', handler: setupStatusHandler },
    { method: 'GET', path: '/callback-done', handler: callbackDoneHandler },
    { method: 'GET', path: '/.well-known/oauth-authorization-server', handler: wellKnownAs },
    { method: 'GET', path: '/.well-known/oauth-protected-resource', handler: wellKnownPr },
    { method: 'GET', path: '/.well-known/jwks.json', handler: wellKnownJwks }
  ])

  return { handler, jwtIssuer, markSetupComplete, markSetupFailed }
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
      `<button type="button" class="oauth-reauth" data-field="${escapeHtml(name)}" aria-label="Re-authorize ${escapeHtml(label)}">` +
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
