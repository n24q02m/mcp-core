/**
 * Tests for the MCP relay password gate wired into the delegated-oauth app.
 *
 * Mirrors the gate semantics PR #158 added to ``createLocalOAuthApp``:
 * when ``MCP_RELAY_PASSWORD`` is set, /authorize is fronted by a
 * cookie-session middleware that redirects unauthenticated requests to
 * /login. /token, /register, /callback, /.well-known/* stay ungated by
 * design — they are machine endpoints or mid-OAuth callbacks.
 *
 * Tests boot a real Node ``http.Server`` per case and drive ``fetch``
 * with ``redirect: 'manual'`` so we can observe the 302 the middleware
 * emits without losing the Location header.
 */

import { mkdtempSync, rmSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createDelegatedOAuthApp, type DelegatedOAuthAppResult } from '../../src/auth/delegated-oauth-app.js'
import { __resetRelayLoginState } from '../../src/auth/relay-login.js'
import { JWTIssuer } from '../../src/oauth/jwt-issuer.js'

interface TestServer {
  url: string
  app: DelegatedOAuthAppResult
  close: () => Promise<void>
}

let tempKeysDir: string
const ORIGINAL_RELAY_PASSWORD = process.env.MCP_RELAY_PASSWORD

beforeEach(() => {
  tempKeysDir = mkdtempSync(join(tmpdir(), 'mcp-core-jwt-'))
  __resetRelayLoginState()
})

afterEach(() => {
  rmSync(tempKeysDir, { recursive: true, force: true })
  if (ORIGINAL_RELAY_PASSWORD === undefined) {
    delete process.env.MCP_RELAY_PASSWORD
  } else {
    process.env.MCP_RELAY_PASSWORD = ORIGINAL_RELAY_PASSWORD
  }
  __resetRelayLoginState()
})

async function startApp(password: string): Promise<TestServer> {
  process.env.MCP_RELAY_PASSWORD = password
  const jwtIssuer = new JWTIssuer('test-delegated-relay', tempKeysDir)
  // ``redirect`` flow with a fake upstream URL — the middleware fires before
  // the upstream is ever contacted in these tests, so the URL is never
  // resolved.
  const app = await createDelegatedOAuthApp({
    serverName: 'test-delegated-relay',
    flow: 'redirect',
    upstream: {
      tokenUrl: 'https://upstream.example/token',
      authorizeUrl: 'https://upstream.example/authorize',
      clientId: 'upstream-client',
      clientSecret: 'upstream-secret',
      scopes: ['read']
    },
    onTokenReceived: () => 'sub-test',
    jwtIssuer
  })
  const server: Server = createServer(app.handler)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address() as AddressInfo
  return {
    url: `http://127.0.0.1:${addr.port}`,
    app,
    close: async () => {
      await app.shutdown()
      await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())))
    }
  }
}

function authorizeQuery(): string {
  const params = new URLSearchParams({
    client_id: 'local-browser',
    redirect_uri: 'http://127.0.0.1:5555/callback',
    state: 'state-xyz',
    code_challenge: 'a'.repeat(43),
    code_challenge_method: 'S256'
  })
  return params.toString()
}

describe('delegated-oauth-app relay password gate', () => {
  it('GET /authorize without cookie redirects to /login when password set', async () => {
    const srv = await startApp('secret123')
    try {
      const resp = await fetch(`${srv.url}/authorize?${authorizeQuery()}`, { redirect: 'manual' })
      expect(resp.status).toBe(302)
      const loc = resp.headers.get('location') ?? ''
      expect(loc.startsWith('/login?next=')).toBe(true)
      expect(decodeURIComponent(loc)).toContain('/authorize')
    } finally {
      await srv.close()
    }
  })

  it('GET /authorize with valid cookie passes the gate (reaches upstream redirect)', async () => {
    const srv = await startApp('secret123')
    try {
      // POST /login to mint a session cookie.
      const loginResp = await fetch(`${srv.url}/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ password: 'secret123', next: '/authorize' }).toString(),
        redirect: 'manual'
      })
      expect(loginResp.status).toBe(302)
      const setCookie = loginResp.headers.get('set-cookie') ?? ''
      expect(setCookie).toContain('mcp_relay_session=')
      const sidMatch = setCookie.match(/mcp_relay_session=([a-f0-9]{64})/)
      expect(sidMatch).not.toBeNull()
      const sid = sidMatch?.[1] ?? ''

      // Now hit /authorize with the cookie. The middleware should pass and
      // the redirect-flow handler should 302 to the upstream authorize URL.
      const resp = await fetch(`${srv.url}/authorize?${authorizeQuery()}`, {
        headers: { cookie: `mcp_relay_session=${sid}` },
        redirect: 'manual'
      })
      expect(resp.status).toBe(302)
      const loc = resp.headers.get('location') ?? ''
      // Middleware fired and the inner handler ran — the redirect target is
      // the upstream authorize URL, NOT /login. We don't assert on the full
      // URL (that's the responsibility of the redirect-flow tests); just
      // that the gate let the request through.
      expect(loc.startsWith('/login')).toBe(false)
      expect(loc).toContain('upstream.example/authorize')
    } finally {
      await srv.close()
    }
  })

  it('GET /authorize without password configured passes through (gate disabled)', async () => {
    const srv = await startApp('')
    try {
      const resp = await fetch(`${srv.url}/authorize?${authorizeQuery()}`, { redirect: 'manual' })
      expect(resp.status).toBe(302)
      const loc = resp.headers.get('location') ?? ''
      expect(loc.startsWith('/login')).toBe(false)
      expect(loc).toContain('upstream.example/authorize')
    } finally {
      await srv.close()
    }
  })

  it('GET /login renders the password form', async () => {
    const srv = await startApp('secret123')
    try {
      const resp = await fetch(`${srv.url}/login`)
      expect(resp.status).toBe(200)
      const html = await resp.text()
      expect(html).toContain('Relay login')
      expect(html).toContain('name="password"')
    } finally {
      await srv.close()
    }
  })

  it('POST /login with wrong password returns 401', async () => {
    const srv = await startApp('secret123')
    try {
      const resp = await fetch(`${srv.url}/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ password: 'wrong', next: '/authorize' }).toString(),
        redirect: 'manual'
      })
      expect(resp.status).toBe(401)
    } finally {
      await srv.close()
    }
  })

  it('GET /token, /register, /setup-status, /.well-known/* are NOT gated', async () => {
    const srv = await startApp('secret123')
    try {
      // /token: missing body returns 400 (parsing error), not redirect.
      const tokResp = await fetch(`${srv.url}/token`, {
        method: 'POST',
        redirect: 'manual'
      })
      expect(tokResp.status).not.toBe(302)
      expect(tokResp.status).toBeGreaterThanOrEqual(400)

      // /register: returns 201 (DCR echoes back).
      const regResp = await fetch(`${srv.url}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
        redirect: 'manual'
      })
      expect(regResp.status).toBe(201)

      // /setup-status: returns 200 JSON.
      const statResp = await fetch(`${srv.url}/setup-status`, { redirect: 'manual' })
      expect(statResp.status).toBe(200)

      // /.well-known/oauth-authorization-server: 200.
      const wellKnown = await fetch(`${srv.url}/.well-known/oauth-authorization-server`, {
        redirect: 'manual'
      })
      expect(wellKnown.status).toBe(200)
    } finally {
      await srv.close()
    }
  })
})
