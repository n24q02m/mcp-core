/**
 * MCP relay edge auth — password gate for ``/authorize``.
 *
 * When ``MCP_RELAY_PASSWORD`` is set, the ``/authorize`` route is fronted by
 * a thin cookie-session middleware. Unauthenticated requests are redirected
 * to ``/login`` where the user submits the password once, gets a 24h
 * ``mcp_relay_session`` cookie, and continues to ``/authorize``.
 *
 * Empty / unset password disables the gate entirely (single-user dev mode).
 *
 * Brute-force protection: 5 wrong submissions per IP within a 15-minute
 * sliding window blocks further attempts with HTTP 429 + ``Retry-After``.
 *
 * Per spec ``2026-05-01-stdio-pure-http-multiuser §4.2.1``. Python parity
 * lives at ``packages/core-py/src/mcp_core/auth/relay_login.py``.
 */
import crypto from 'node:crypto'
import { renderFormShell } from './credential-form.js'

interface SessionEntry {
  expiresAt: number
}
interface FailEntry {
  count: number
  firstAt: number
}

const sessions = new Map<string, SessionEntry>()
const fails = new Map<string, FailEntry>()
const SESSION_TTL_MS = 24 * 60 * 60 * 1000
const FAIL_WINDOW_MS = 15 * 60 * 1000
const FAIL_LIMIT = 5

let configuredPassword = ''

export function configureRelayLogin(password: string): void {
  configuredPassword = password ?? ''
}

/**
 * Reset module-scoped state. TEST-ONLY — reset between cases so brute-force
 * counters from one test don't bleed into the next.
 */
export function __resetRelayLoginState(): void {
  sessions.clear()
  fails.clear()
  configuredPassword = ''
}

function timingSafeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  const isLengthEqual = ab.length === bb.length
  const compareB = isLengthEqual ? bb : ab
  return crypto.timingSafeEqual(ab, compareB) && isLengthEqual
}

function bumpFail(ip: string): { blocked: boolean; retryAfter: number } {
  const now = Date.now()
  const entry = fails.get(ip)
  if (!entry || now - entry.firstAt > FAIL_WINDOW_MS) {
    fails.set(ip, { count: 1, firstAt: now })
    return { blocked: false, retryAfter: 0 }
  }
  entry.count += 1
  if (entry.count > FAIL_LIMIT) {
    return {
      blocked: true,
      retryAfter: Math.ceil((FAIL_WINDOW_MS - (now - entry.firstAt)) / 1000)
    }
  }
  return { blocked: false, retryAfter: 0 }
}

function clearFail(ip: string): void {
  fails.delete(ip)
}

/**
 * Minimal req/res shapes the handlers + middleware need. We accept the
 * Express-style fields directly so consumers can adapt the project's
 * IncomingMessage / ServerResponse pair (or the Express runtime, or test
 * stubs) without dragging the full DOM types into this module.
 */
export interface RelayLoginRequest {
  cookies?: Record<string, string | undefined>
  originalUrl?: string
  query?: Record<string, string | undefined>
  body?: Record<string, string | undefined>
  ip?: string
}

export interface RelayCookieOptions {
  httpOnly?: boolean
  secure?: boolean
  sameSite?: 'lax' | 'strict' | 'none'
  maxAge?: number
}

export interface RelayLoginResponse {
  redirect: (url: string) => unknown
  status: (code: number) => RelayLoginResponse
  send: (body?: unknown) => unknown
  cookie: (name: string, value: string, options?: RelayCookieOptions) => unknown
  header?: (name: string, value: string) => unknown
  set?: (name: string, value: string) => unknown
}

/**
 * Express-style middleware adapter.
 *
 * Pass-through when no password configured. Otherwise: read
 * ``mcp_relay_session`` cookie, allow if present + unexpired, redirect to
 * ``/login?next=<encoded>`` otherwise.
 */
export function createRelayLoginMiddleware(opts: { password: string }) {
  return async (req: RelayLoginRequest, res: Pick<RelayLoginResponse, 'redirect'>, next: () => void): Promise<void> => {
    if (!opts.password) {
      next()
      return
    }
    const sid = req.cookies?.mcp_relay_session
    const entry = sid ? sessions.get(sid) : undefined
    if (entry && entry.expiresAt > Date.now()) {
      next()
      return
    }
    const next_ = encodeURIComponent(req.originalUrl ?? '/authorize')
    res.redirect(`/login?next=${next_}`)
  }
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    const entities: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }
    return entities[c] ?? c
  })
}

/**
 * Validates the ``next`` parameter to prevent Open Redirect vulnerabilities.
 *
 * It must start with a single ``/`` and NOT be followed by another ``/``,
 * ``\\``, or any whitespace/control character that some browsers might
 * normalize into a protocol-relative URL.
 */
function getSafeNext(input: unknown): string {
  const next = String(input ?? '/authorize')
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\') || next.startsWith('\\\\')) {
    return '/authorize'
  }
  // Block cases like "/ google.com" or "/\tgoogle.com" (ASCII <= 32).
  if (next.length > 1 && next.charCodeAt(1) <= 32) {
    return '/authorize'
  }
  return next
}

function renderLoginForm(next: string, errorMsg?: string): string {
  const safeNext = escapeHtml(String(next))
  const errorHtml = errorMsg
    ? `\n            <div id="login-error" class="status-box error" role="alert" style="display: block; margin-bottom: 1.25rem; margin-top: 0;">\n                ${escapeHtml(errorMsg)}\n            </div>`
    : ''

  const ariaAttributes = errorMsg ? ' aria-invalid="true" aria-errormessage="login-error"' : ''

  return `    <div class="container">
        <div class="card">
            <div class="server-header">
                <h1 class="server-name">Relay login</h1>
                <div class="server-id">mcp-relay</div>
                <p class="server-description">Enter the relay password shared by your deployer.</p>
            </div>${errorHtml}

            <p class="form-title" id="form-title">Authenticate</p>

            <form method="POST" action="/login" aria-labelledby="form-title">
                <!-- nosemgrep: javascript.express.security.injection.raw-html-format.raw-html-format -- safeNext is escapeHtml(next) -->
                <input type="hidden" name="next" value="${safeNext}">
                <div class="field-group">
                    <label for="field-password" class="field-label">
                        Relay password
                        <span class="required-badge" aria-hidden="true">Required</span>
                    </label>
                    <input
                        id="field-password"
                        type="password"
                        name="password"
                        class="field-input"
                        placeholder="Relay password"
                        autocomplete="current-password"
                        autocorrect="off"
                        autocapitalize="off"
                        spellcheck="false"
                        required
                        autofocus${ariaAttributes}
                    />
                </div>

                <button type="submit" class="submit-btn">Continue</button>
            </form>
        </div>
    </div>`
}

export async function loginGetHandler(
  req: Pick<RelayLoginRequest, 'query'>,
  res: Pick<RelayLoginResponse, 'send' | 'set'>
): Promise<void> {
  const next = getSafeNext(req.query?.next)
  res.set?.('Content-Type', 'text/html')
  res.send(renderFormShell('Relay login', renderLoginForm(next)))
}

export async function loginPostHandler(
  req: Pick<RelayLoginRequest, 'body' | 'ip'>,
  res: RelayLoginResponse
): Promise<void> {
  const ip = req.ip ?? 'unknown'
  const now = Date.now()
  const failEntry = fails.get(ip)
  if (failEntry && now - failEntry.firstAt < FAIL_WINDOW_MS && failEntry.count >= FAIL_LIMIT) {
    res.header?.('Retry-After', String(Math.ceil((FAIL_WINDOW_MS - (now - failEntry.firstAt)) / 1000)))
    res.status(429).send('Too many login attempts. Try again later.')
    return
  }
  const password = String(req.body?.password ?? '')
  const next = getSafeNext(req.body?.next)
  if (!configuredPassword || !timingSafeEqual(password, configuredPassword)) {
    bumpFail(ip)
    res.set?.('Content-Type', 'text/html')
    res.status(401).send(renderFormShell('Relay login', renderLoginForm(next, 'Invalid password. Please try again.')))
    return
  }
  clearFail(ip)
  const sid = crypto.randomBytes(32).toString('hex')
  sessions.set(sid, { expiresAt: Date.now() + SESSION_TTL_MS })
  res.cookie('mcp_relay_session', sid, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: SESSION_TTL_MS
  })
  res.redirect(next)
}
