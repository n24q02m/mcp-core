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
