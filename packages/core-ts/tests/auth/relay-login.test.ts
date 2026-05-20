/**
 * Tests for the MCP relay password gate.
 *
 * The gate is a lightweight cookie-session middleware that fronts ``/authorize``
 * (the credential-collection form). When ``MCP_RELAY_PASSWORD`` is empty the
 * gate is disabled and the middleware passes through; when set, an unrecognised
 * cookie redirects the user to ``/login`` where they exchange the password for
 * a session cookie.
 *
 * Tests are intentionally framework-agnostic: handlers receive plain objects
 * matching ``RelayLoginRequest`` / ``RelayLoginResponse`` so the same handlers
 * can be adapted to either Express or the project's lightweight router
 * without coupling tests to either runtime.
 */
import { beforeEach, describe, expect, it } from 'vitest'
import {
  __resetRelayLoginState,
  configureRelayLogin,
  createRelayLoginMiddleware,
  loginGetHandler,
  loginPostHandler,
  type RelayCookieOptions,
  type RelayLoginRequest,
  type RelayLoginResponse
} from '../../src/auth/relay-login.js'

interface CookieRecord {
  name: string
  value: string
  options?: RelayCookieOptions
}

function makeResponseStub(): {
  res: RelayLoginResponse
  status: () => number
  cookie: () => CookieRecord | null
  redirect: () => string | null
  retryAfter: () => string | null
} {
  let statusCode = 0
  let cookieRecord: CookieRecord | null = null
  let redirectUrl: string | null = null
  let retryAfter: string | null = null
  const res: RelayLoginResponse = {
    status: (code) => {
      statusCode = code
      return res
    },
    send: () => res,
    cookie: (name, value, options) => {
      cookieRecord = { name, value, options }
      return res
    },
    redirect: (url) => {
      redirectUrl = url
      return res
    },
    header: (_name, value) => {
      retryAfter = String(value)
      return res
    },
    set: () => res
  }
  return {
    res,
    status: () => statusCode,
    cookie: () => cookieRecord,
    redirect: () => redirectUrl,
    retryAfter: () => retryAfter
  }
}

describe('relay-login', () => {
  beforeEach(() => {
    __resetRelayLoginState()
  })

  it('empty env disables gate (middleware passes through)', async () => {
    configureRelayLogin('')
    const mw = createRelayLoginMiddleware({ password: '' })
    const req: RelayLoginRequest = { cookies: {} }
    const stub = makeResponseStub()
    let nextCalled = false
    await mw(req, stub.res, () => {
      nextCalled = true
    })
    expect(nextCalled).toBe(true)
    expect(stub.redirect()).toBeNull()
  })

  it('missing cookie redirects to /login with next param', async () => {
    configureRelayLogin('secret123')
    const mw = createRelayLoginMiddleware({ password: 'secret123' })
    const req: RelayLoginRequest = { cookies: {}, originalUrl: '/authorize?session=abc' }
    const stub = makeResponseStub()
    let nextCalled = false
    await mw(req, stub.res, () => {
      nextCalled = true
    })
    expect(nextCalled).toBe(false)
    expect(stub.redirect()).toBe('/login?next=%2Fauthorize%3Fsession%3Dabc')
  })

  it('valid cookie passes middleware', async () => {
    configureRelayLogin('secret123')
    // Pre-seed session via POST.
    const postReq: RelayLoginRequest = {
      body: { password: 'secret123', next: '/authorize' },
      ip: '1.2.3.4'
    }
    const postStub = makeResponseStub()
    await loginPostHandler(postReq, postStub.res)
    const cookie = postStub.cookie()
    expect(cookie).not.toBeNull()
    expect(cookie?.value ?? '').toMatch(/^[a-f0-9]{64}$/)

    // Now hit middleware with the cookie.
    const mw = createRelayLoginMiddleware({ password: 'secret123' })
    const req: RelayLoginRequest = { cookies: { mcp_relay_session: cookie?.value } }
    const stub = makeResponseStub()
    let nextCalled = false
    await mw(req, stub.res, () => {
      nextCalled = true
    })
    expect(nextCalled).toBe(true)
    expect(stub.redirect()).toBeNull()
  })

  it('wrong password 401', async () => {
    configureRelayLogin('secret123')
    const req: RelayLoginRequest = {
      body: { password: 'wrong', next: '/authorize' },
      ip: '1.2.3.5'
    }
    const stub = makeResponseStub()
    await loginPostHandler(req, stub.res)
    expect(stub.status()).toBe(401)
  })

  it('login GET reuses shared form shell (visual parity with credential form)', async () => {
    let captured = ''
    const res: Pick<RelayLoginResponse, 'send' | 'set'> = {
      send: (body?: unknown) => {
        captured = String(body ?? '')
        return undefined as never
      },
      set: () => undefined as never
    }
    await loginGetHandler({ query: { next: '/authorize?session=abc' } }, res)
    // Shared shell markers (head + global CSS variables).
    expect(captured).toContain('<title>Relay login</title>')
    expect(captured).toContain('#0f0f0f')
    // Card classes carried over from credential-form.
    expect(captured).toContain('class="container"')
    expect(captured).toContain('class="card"')
    expect(captured).toContain('class="server-name"')
    // Field-group structure replaces the bare <input>.
    expect(captured).toContain('class="field-group"')
    expect(captured).toContain('class="field-label"')
    expect(captured).toContain('class="field-input"')
    expect(captured).toContain('class="required-badge"')
    expect(captured).toContain('class="submit-btn"')
    // Behavioural contract preserved.
    expect(captured).toContain('action="/login"')
    expect(captured).toContain('method="POST"')
    expect(captured).toContain('name="next" value="/authorize?session=abc"')
    expect(captured).toContain('type="password"')
    expect(captured).toContain('name="password"')
  })

  it('login GET escapes the next query param', async () => {
    let captured = ''
    const res: Pick<RelayLoginResponse, 'send' | 'set'> = {
      send: (body?: unknown) => {
        captured = String(body ?? '')
        return undefined as never
      },
      set: () => undefined as never
    }
    await loginGetHandler({ query: { next: '/authorize?x=<script>alert("xss")</script>' } }, res)
    expect(captured).not.toContain('<script>')
    expect(captured).toContain('&lt;script&gt;')
    expect(captured).toContain('&quot;')
  })

  it('prevents open redirect on successful login', async () => {
    configureRelayLogin('secret123')
    const req: RelayLoginRequest = {
      body: { password: 'secret123', next: 'https://evil.com' },
      ip: '1.2.3.4'
    }
    const stub = makeResponseStub()
    await loginPostHandler(req, stub.res)
    expect(stub.redirect()).toBe('/authorize')
  })

  it('brute force 6th attempt within 15min returns 429', async () => {
    configureRelayLogin('secret123')
    const ip = '9.9.9.9'
    for (let i = 0; i < 5; i++) {
      const req: RelayLoginRequest = { body: { password: 'wrong', next: '/' }, ip }
      const stub = makeResponseStub()
      await loginPostHandler(req, stub.res)
    }
    const req6: RelayLoginRequest = { body: { password: 'wrong', next: '/' }, ip }
    const stub6 = makeResponseStub()
    await loginPostHandler(req6, stub6.res)
    expect(stub6.status()).toBe(429)
    expect(stub6.retryAfter()).not.toBeNull()
  })
})
