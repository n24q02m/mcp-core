/**
 * Local OAuth 2.1 Authorization Server as an HTTP request handler.
 *
 * Provides a self-hosted Authorization Server for single-user MCP servers.
 * Implements the OAuth 2.1 PKCE flow with credential collection via a
 * browser-rendered form.
 *
 * Routes:
 * - GET  /authorize                                -- Render credential form
 * - POST /authorize                                -- Save credentials, return auth code
 * - POST /otp                                      -- Submit multi-step credential (OTP / 2FA password)
 * - POST /token                                    -- Exchange auth code + PKCE verifier for JWT
 * - GET  /setup-status                             -- Poll background setup completion
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
 * Callback invoked when the user submits credentials via POST /authorize.
 *
 * Return ``null`` to finish the flow or a ``next_step`` dict to trigger a
 * follow-up (OAuth device code, OTP, 2FA password, etc). May be sync or async.
 */
export type CredentialsCallback = (creds: Record<string, string>) => NextStep | null | Promise<NextStep | null>

/**
 * Callback invoked when the user submits step input via POST /otp.
 *
 * Return ``null`` to complete the flow, a ``{type: "otp_required" |
 * "password_required", ...}`` dict to chain to another step, or
 * ``{type: "error", text: "..."}`` to reject the current input and allow
 * retry. Callbacks comparing secrets MUST use a timing-safe comparison.
 * May be sync or async.
 */
export type StepCallback = (data: Record<string, string>) => NextStep | null | Promise<NextStep | null>

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
}

export interface LocalOAuthAppResult {
  /** HTTP request handler to mount on a Node ``http.Server``. */
  handler: RequestHandler
  /** JWT issuer, needed by the transport layer to verify Bearer tokens. */
  jwtIssuer: JWTIssuer
  /** Mark a background setup step as complete (polled by GET /setup-status). */
  markSetupComplete: (key?: string) => void
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
}

interface AuthCodeEntry {
  codeChallenge: string
  codeChallengeMethod: string
  createdAt: number
}

interface PendingStep {
  active: boolean
  createdAt: number
  attempts: number
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

/** Derive the public base URL of this request (protocol + host, no trailing slash). */
function getBaseUrl(req: IncomingMessage): string {
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

  function markPendingStep(): void {
    pendingStep = { active: true, createdAt: Date.now(), attempts: 0 }
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
    pendingSessions.set(nonce, {
      clientId,
      redirectUri,
      state,
      codeChallenge,
      codeChallengeMethod,
      createdAt: Date.now()
    })
    pruneExpired(pendingSessions, SESSION_TTL_S * 1000)

    const base = getBaseUrl(req)
    const submitUrl = `${base}/authorize?nonce=${nonce}`
    const html = renderCredentialForm(options.relaySchema, { submitUrl })
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
    let nextStep: NextStep | null = null
    if (options.onCredentialsSaved !== undefined) {
      try {
        const result = await options.onCredentialsSaved(credentials)
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

    // Generate auth code.
    const authCode = randomBytes(32).toString('base64url')
    authCodes.set(authCode, {
      codeChallenge: session.codeChallenge,
      codeChallengeMethod: session.codeChallengeMethod,
      createdAt: Date.now()
    })
    pruneExpired(authCodes, AUTH_CODE_TTL_S * 1000)

    const separator = session.redirectUri.includes('?') ? '&' : '?'
    const redirectUrl = `${session.redirectUri}${separator}code=${authCode}&state=${session.state}`

    const body: Record<string, unknown> = { ok: true, redirect_url: redirectUrl }
    if (nextStep !== null) {
      body.next_step = nextStep
      // If next_step requires additional input (OTP or 2FA password),
      // activate pending step session so /otp endpoint accepts input.
      const stepType = nextStep.type
      if (stepType === 'otp_required' || stepType === 'password_required') {
        markPendingStep()
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

    const accessToken = await jwtIssuer.issueAccessToken('local-user')
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

    // 6. Dispatch to step callback.
    let nextStep: NextStep | null = null
    if (options.onStepSubmitted !== undefined) {
      try {
        const result = await options.onStepSubmitted(stepData)
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
    if (nextStep !== null && (nextStep.type === 'otp_required' || nextStep.type === 'password_required')) {
      markPendingStep()
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

  function markSetupComplete(key = 'gdrive'): void {
    setupStatus[key] = 'complete'
  }

  const handler = createRouter([
    { method: 'GET', path: '/authorize', handler: authorize },
    { method: 'POST', path: '/authorize', handler: authorize },
    { method: 'POST', path: '/token', handler: token },
    { method: 'POST', path: '/otp', handler: otpHandler },
    { method: 'GET', path: '/setup-status', handler: setupStatusHandler },
    { method: 'GET', path: '/.well-known/oauth-authorization-server', handler: wellKnownAs },
    { method: 'GET', path: '/.well-known/oauth-protected-resource', handler: wellKnownPr }
  ])

  return { handler, jwtIssuer, markSetupComplete }
}
