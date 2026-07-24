/**
 * Integration tests for the local OAuth 2.1 Authorization Server handler.
 *
 * Spins up a real Node ``http.Server`` per test and drives the full PKCE
 * flow via ``fetch``. Mirrors coverage of the Python test_local_oauth_app.py.
 */

import { createHash, randomBytes } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import type { RelayConfigSchema } from '../../src/auth/credential-form.js'
import { createLocalOAuthApp, type LocalOAuthAppResult } from '../../src/auth/local-oauth-app.js'
import { deriveStableSub } from '../../src/auth/stable-sub.js'
import { JWTIssuer } from '../../src/oauth/jwt-issuer.js'

interface TestServer {
  url: string
  close: () => Promise<void>
  app: LocalOAuthAppResult
}

const SCHEMA: RelayConfigSchema = {
  server: 'test-server',
  displayName: 'Test Server',
  description: 'Integration test server',
  fields: [
    { key: 'api_key', label: 'API Key', type: 'text', required: true },
    { key: 'secret', label: 'Secret', type: 'password', required: false }
  ]
}

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url')
  return { verifier, challenge }
}

function extractNonce(html: string): string {
  const match = html.match(/nonce=([A-Za-z0-9_-]+)/)
  if (!match) throw new Error('No nonce in HTML')
  return match[1]
}

let tempKeysDir: string

beforeEach(() => {
  tempKeysDir = mkdtempSync(join(tmpdir(), 'mcp-core-jwt-'))
})

afterEach(() => {
  rmSync(tempKeysDir, { recursive: true, force: true })
})

async function startApp(
  options: {
    onCredentialsSaved?: Parameters<typeof createLocalOAuthApp>[0]['onCredentialsSaved']
    onStepSubmitted?: Parameters<typeof createLocalOAuthApp>[0]['onStepSubmitted']
    stableSubEnabled?: boolean
  } = {}
): Promise<TestServer> {
  const jwtIssuer = new JWTIssuer('test-server', tempKeysDir)
  const app = await createLocalOAuthApp({
    serverName: 'test-server',
    relaySchema: SCHEMA,
    jwtIssuer,
    onCredentialsSaved: options.onCredentialsSaved,
    onStepSubmitted: options.onStepSubmitted,
    stableSubEnabled: options.stableSubEnabled
  })
  const server: Server = createServer(app.handler)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address() as AddressInfo
  return {
    url: `http://127.0.0.1:${addr.port}`,
    app,
    close: () => new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())))
  }
}

describe('GET /authorize', () => {
  it('renders credential form HTML with embedded nonce', async () => {
    const srv = await startApp()
    try {
      const { challenge } = pkce()
      const params = new URLSearchParams({
        client_id: 'test-client',
        redirect_uri: 'http://localhost:5555/callback',
        state: 'xyz',
        code_challenge: challenge,
        code_challenge_method: 'S256'
      })
      const resp = await fetch(`${srv.url}/authorize?${params.toString()}`)
      expect(resp.status).toBe(200)
      expect(resp.headers.get('content-type')).toContain('text/html')
      const html = await resp.text()
      expect(html).toContain('Test Server')
      expect(html).toContain('API Key')
      expect(html).toMatch(/nonce=[A-Za-z0-9_-]+/)
    } finally {
      await srv.close()
    }
  })

  it('returns 400 when required parameters are missing', async () => {
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/authorize?client_id=x`)
      expect(resp.status).toBe(400)
      const body = (await resp.json()) as Record<string, string>
      expect(body.error).toBe('invalid_request')
    } finally {
      await srv.close()
    }
  })
})

describe('POST /authorize', () => {
  it('accepts credentials and returns auth code in redirect_url', async () => {
    const received: Record<string, string>[] = []
    const srv = await startApp({
      onCredentialsSaved: (creds) => {
        received.push(creds)
        return null
      }
    })
    try {
      const { challenge } = pkce()
      const params = new URLSearchParams({
        client_id: 'test-client',
        redirect_uri: 'http://localhost:5555/callback',
        state: 'xyz',
        code_challenge: challenge
      })
      const getResp = await fetch(`${srv.url}/authorize?${params.toString()}`)
      const nonce = extractNonce(await getResp.text())

      const postResp = await fetch(`${srv.url}/authorize?nonce=${nonce}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: 'sk-test', secret: 'shh' })
      })
      expect(postResp.status).toBe(200)
      const body = (await postResp.json()) as Record<string, unknown>
      expect(body.ok).toBe(true)
      expect(typeof body.redirect_url).toBe('string')
      expect(body.redirect_url as string).toContain('code=')
      expect(body.redirect_url as string).toContain('state=xyz')
      expect(received).toEqual([{ api_key: 'sk-test', secret: 'shh' }])
    } finally {
      await srv.close()
    }
  })

  it('includes iss in the authorization redirect (RFC 9207 / SEP-2468)', async () => {
    const srv = await startApp({ onCredentialsSaved: () => null })
    try {
      const { challenge } = pkce()
      const params = new URLSearchParams({
        client_id: 'c',
        redirect_uri: 'http://localhost:5555/callback',
        state: 'xyz',
        code_challenge: challenge
      })
      const getResp = await fetch(`${srv.url}/authorize?${params.toString()}`)
      const nonce = extractNonce(await getResp.text())
      const postResp = await fetch(`${srv.url}/authorize?nonce=${nonce}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: 'k' })
      })
      const redirectUrl = ((await postResp.json()) as { redirect_url: string }).redirect_url
      // iss MUST equal the AS issuer (this server's base URL), URL-encoded in
      // the redirect and decoded back by URL.searchParams.
      expect(new URL(redirectUrl).searchParams.get('iss')).toBe(srv.url)
    } finally {
      await srv.close()
    }
  })

  it('rejects POST with unknown nonce', async () => {
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/authorize?nonce=bogus`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      })
      expect(resp.status).toBe(400)
    } finally {
      await srv.close()
    }
  })

  it('passes a unique per-session subject to onCredentialsSaved and the issued JWT', async () => {
    // Multi-user isolation primitive: two concurrent browser sessions MUST
    // receive distinct ``sub`` values in onCredentialsSaved AND the resulting
    // /token JWT must carry the SAME sub that was used when credentials were
    // saved. Otherwise remote-relay consumers cannot key their credential
    // store by user, which is the bug that let email+telegram share a single
    // config.enc across all public-URL visitors.
    const savedSubjects: string[] = []
    const srv = await startApp({
      onCredentialsSaved: (_creds, context) => {
        savedSubjects.push(context.sub)
        return null
      }
    })
    try {
      async function runFlow(tag: string): Promise<string> {
        const { verifier, challenge } = pkce()
        const params = new URLSearchParams({
          client_id: `client-${tag}`,
          redirect_uri: `http://localhost:5555/cb-${tag}`,
          state: `st-${tag}`,
          code_challenge: challenge
        })
        const getResp = await fetch(`${srv.url}/authorize?${params.toString()}`)
        const nonce = extractNonce(await getResp.text())
        const postResp = await fetch(`${srv.url}/authorize?nonce=${nonce}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ api_key: `key-${tag}` })
        })
        const code = new URL(((await postResp.json()) as { redirect_url: string }).redirect_url).searchParams.get(
          'code'
        ) as string
        const tokenResp = await fetch(`${srv.url}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: verifier }).toString()
        })
        const body = (await tokenResp.json()) as { access_token: string }
        const payload = await srv.app.jwtIssuer.verifyAccessToken(body.access_token)
        return payload.sub as string
      }

      const [subA, subB] = await Promise.all([runFlow('a'), runFlow('b')])
      // 1. Two sessions → two distinct subjects (not collapsed to 'local-user')
      expect(subA).not.toBe(subB)
      expect(subA).not.toBe('local-user')
      expect(subB).not.toBe('local-user')
      // 2. The JWT subject matches what was passed to onCredentialsSaved
      expect(savedSubjects).toContain(subA)
      expect(savedSubjects).toContain(subB)
      expect(savedSubjects.length).toBe(2)
      expect(new Set(savedSubjects).size).toBe(2)
    } finally {
      await srv.close()
    }
  })
})

describe('stable subject', () => {
  const SECRET = 'stable-sub-test-secret'
  const DERIVED = deriveStableSub('matthias', 'test-server', SECRET)
  let originalSecret: string | undefined

  beforeEach(() => {
    originalSecret = process.env.CREDENTIAL_SECRET
    process.env.CREDENTIAL_SECRET = SECRET
  })

  afterEach(() => {
    if (originalSecret === undefined) delete process.env.CREDENTIAL_SECRET
    else process.env.CREDENTIAL_SECRET = originalSecret
  })

  async function getAuthorizeHtml(srv: TestServer): Promise<string> {
    const { challenge } = pkce()
    const params = new URLSearchParams({
      client_id: 'c',
      redirect_uri: 'http://localhost:5555/cb',
      state: 's',
      code_challenge: challenge
    })
    const resp = await fetch(`${srv.url}/authorize?${params.toString()}`)
    return await resp.text()
  }

  /** Drive GET -> POST /authorize once; the callback capture is the assertion surface. */
  async function submit(srv: TestServer, body: Record<string, string>): Promise<void> {
    const nonce = extractNonce(await getAuthorizeHtml(srv))
    const resp = await fetch(`${srv.url}/authorize?nonce=${nonce}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
    expect(resp.status).toBe(200)
  }

  it('renders the username field only when stableSubEnabled is set', async () => {
    const on = await startApp({ stableSubEnabled: true })
    try {
      expect(await getAuthorizeHtml(on)).toContain('name="__sub_username"')
    } finally {
      await on.close()
    }
    const off = await startApp()
    try {
      expect(await getAuthorizeHtml(off)).not.toContain('__sub_username')
    } finally {
      await off.close()
    }
  })

  it('replaces the random subject with a derived one when a username is submitted', async () => {
    const subs: string[] = []
    const srv = await startApp({
      stableSubEnabled: true,
      onCredentialsSaved: (_creds, context) => {
        subs.push(context.sub)
        return null
      }
    })
    try {
      await submit(srv, { api_key: 'k', __sub_username: 'matthias' })
      await submit(srv, { api_key: 'k', __sub_username: '  MATTHIAS  ' })
      // Stable across two independent authorize round-trips, and equal to the
      // cross-language derivation (same bucket a returning user reaches).
      expect(subs).toEqual([DERIVED, DERIVED])
    } finally {
      await srv.close()
    }
  })

  it('never persists the reserved field as a credential', async () => {
    const received: Record<string, string>[] = []
    const srv = await startApp({
      stableSubEnabled: true,
      onCredentialsSaved: (creds) => {
        received.push(creds)
        return null
      }
    })
    try {
      await submit(srv, { api_key: 'k', __sub_username: 'matthias' })
      expect(received).toEqual([{ api_key: 'k' }])
    } finally {
      await srv.close()
    }
  })

  it('keeps the random subject when the username is blank', async () => {
    const subs: string[] = []
    const srv = await startApp({
      stableSubEnabled: true,
      onCredentialsSaved: (_creds, context) => {
        subs.push(context.sub)
        return null
      }
    })
    try {
      await submit(srv, { api_key: 'k', __sub_username: '   ' })
      await submit(srv, { api_key: 'k', __sub_username: '   ' })
      expect(subs[0]).not.toBe(DERIVED)
      expect(subs[0]).not.toBe(subs[1])
      expect(subs[0]).toMatch(/^[A-Za-z0-9_-]{22}$/)
    } finally {
      await srv.close()
    }
  })

  it('keeps the random subject when stableSubEnabled is false', async () => {
    const subs: string[] = []
    const received: Record<string, string>[] = []
    const srv = await startApp({
      onCredentialsSaved: (creds, context) => {
        received.push(creds)
        subs.push(context.sub)
        return null
      }
    })
    try {
      await submit(srv, { api_key: 'k', __sub_username: 'matthias' })
      await submit(srv, { api_key: 'k', __sub_username: 'matthias' })
      expect(subs[0]).not.toBe(DERIVED)
      expect(subs[0]).not.toBe(subs[1])
      // The reserved key is stripped regardless of the flag.
      expect(received).toEqual([{ api_key: 'k' }, { api_key: 'k' }])
    } finally {
      await srv.close()
    }
  })
})

describe('POST /token', () => {
  it('exchanges authorization code + verifier for a JWT access token', async () => {
    const srv = await startApp()
    try {
      const { verifier, challenge } = pkce()
      const params = new URLSearchParams({
        client_id: 'c',
        redirect_uri: 'http://localhost:5555/cb',
        state: 's',
        code_challenge: challenge
      })
      const getResp = await fetch(`${srv.url}/authorize?${params.toString()}`)
      const nonce = extractNonce(await getResp.text())
      const postResp = await fetch(`${srv.url}/authorize?nonce=${nonce}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: 'k' })
      })
      const redirectUrl = (await postResp.json()).redirect_url as string
      const code = new URL(redirectUrl).searchParams.get('code') as string

      const tokenResp = await fetch(`${srv.url}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          code_verifier: verifier
        }).toString()
      })
      expect(tokenResp.status).toBe(200)
      const body = (await tokenResp.json()) as Record<string, unknown>
      expect(body.token_type).toBe('Bearer')
      expect(body.expires_in).toBe(3600)
      expect(typeof body.access_token).toBe('string')
      // Issue #261: authorization_code grant now also returns a refresh token
      // + offline_access scope so long-running clients can renew.
      expect(typeof body.refresh_token).toBe('string')
      expect(body.scope).toBe('offline_access')
      const payload = await srv.app.jwtIssuer.verifyAccessToken(body.access_token as string)
      // Subject is a per-authorize-request UUID (22 base64url chars for 16 random bytes),
      // NOT the legacy static 'local-user'. This enables multi-user credential
      // isolation in remote-relay mode — each browser session gets its own sub.
      expect(typeof payload.sub).toBe('string')
      expect((payload.sub as string).length).toBeGreaterThanOrEqual(20)
      expect(payload.sub).not.toBe('local-user')
      const refreshPayload = await srv.app.jwtIssuer.verifyRefreshToken(body.refresh_token as string)
      expect(refreshPayload.sub).toBe(payload.sub)
    } finally {
      await srv.close()
    }
  })

  it('rejects unsupported grant_type', async () => {
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'password' }).toString()
      })
      expect(resp.status).toBe(400)
      expect(((await resp.json()) as Record<string, string>).error).toBe('unsupported_grant_type')
    } finally {
      await srv.close()
    }
  })

  it('rejects wrong PKCE verifier with invalid_grant', async () => {
    const srv = await startApp()
    try {
      const { challenge } = pkce()
      const params = new URLSearchParams({
        client_id: 'c',
        redirect_uri: 'http://localhost/cb',
        state: 's',
        code_challenge: challenge
      })
      const getResp = await fetch(`${srv.url}/authorize?${params.toString()}`)
      const nonce = extractNonce(await getResp.text())
      const postResp = await fetch(`${srv.url}/authorize?nonce=${nonce}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: 'k' })
      })
      const redirectUrl = (await postResp.json()).redirect_url as string
      const code = new URL(redirectUrl).searchParams.get('code') as string

      const wrongVerifier = randomBytes(32).toString('base64url')
      const tokenResp = await fetch(`${srv.url}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          code_verifier: wrongVerifier
        }).toString()
      })
      expect(tokenResp.status).toBe(400)
      expect(((await tokenResp.json()) as Record<string, string>).error).toBe('invalid_grant')
    } finally {
      await srv.close()
    }
  })
})

describe('POST /token refresh_token grant (issue #261)', () => {
  async function completeAuthCodeFlow(srv: TestServer): Promise<Record<string, unknown>> {
    const { verifier, challenge } = pkce()
    const params = new URLSearchParams({
      client_id: 'c',
      redirect_uri: 'http://localhost:5555/cb',
      state: 's',
      code_challenge: challenge
    })
    const getResp = await fetch(`${srv.url}/authorize?${params.toString()}`)
    const nonce = extractNonce(await getResp.text())
    const postResp = await fetch(`${srv.url}/authorize?nonce=${nonce}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: 'k' })
    })
    const code = new URL(((await postResp.json()) as { redirect_url: string }).redirect_url).searchParams.get(
      'code'
    ) as string
    const tokenResp = await fetch(`${srv.url}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: verifier }).toString()
    })
    return (await tokenResp.json()) as Record<string, unknown>
  }

  it('returns a NEW access + refresh token for a valid refresh_token grant', async () => {
    const srv = await startApp()
    try {
      const original = await completeAuthCodeFlow(srv)
      const originalSub = (await srv.app.jwtIssuer.verifyRefreshToken(original.refresh_token as string)).sub

      const resp = await fetch(`${srv.url}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: original.refresh_token as string
        }).toString()
      })
      expect(resp.status).toBe(200)
      const body = (await resp.json()) as Record<string, unknown>
      expect(body.token_type).toBe('Bearer')
      expect(body.expires_in).toBe(3600)
      expect(body.scope).toBe('offline_access')
      expect(typeof body.access_token).toBe('string')
      expect(typeof body.refresh_token).toBe('string')

      const newAccess = await srv.app.jwtIssuer.verifyAccessToken(body.access_token as string)
      const newRefresh = await srv.app.jwtIssuer.verifyRefreshToken(body.refresh_token as string)
      expect(newAccess.sub).toBe(originalSub)
      expect(newRefresh.sub).toBe(originalSub)
    } finally {
      await srv.close()
    }
  })

  it('rejects a refresh_token grant with no refresh_token (invalid_request)', async () => {
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token' }).toString()
      })
      expect(resp.status).toBe(400)
      expect(((await resp.json()) as Record<string, string>).error).toBe('invalid_request')
    } finally {
      await srv.close()
    }
  })

  it('rejects a bogus refresh_token (invalid_grant)', async () => {
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: 'not-a-jwt' }).toString()
      })
      expect(resp.status).toBe(400)
      expect(((await resp.json()) as Record<string, string>).error).toBe('invalid_grant')
    } finally {
      await srv.close()
    }
  })

  it('rejects an access token presented at the refresh grant (invalid_grant)', async () => {
    const srv = await startApp()
    try {
      const original = await completeAuthCodeFlow(srv)
      const resp = await fetch(`${srv.url}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: original.access_token as string
        }).toString()
      })
      expect(resp.status).toBe(400)
      expect(((await resp.json()) as Record<string, string>).error).toBe('invalid_grant')
    } finally {
      await srv.close()
    }
  })
})

describe('well-known metadata', () => {
  it('serves RFC 8414 authorization server metadata', async () => {
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/.well-known/oauth-authorization-server`)
      expect(resp.status).toBe(200)
      const body = (await resp.json()) as Record<string, unknown>
      expect(body.issuer).toBe(srv.url)
      expect(body.authorization_endpoint).toBe(`${srv.url}/authorize`)
      expect(body.token_endpoint).toBe(`${srv.url}/token`)
      expect(body.code_challenge_methods_supported).toEqual(['S256'])
      // RFC 9207 / SEP-2468: advertise iss support in the authorization response.
      expect(body.authorization_response_iss_parameter_supported).toBe(true)
    } finally {
      await srv.close()
    }
  })

  it('serves RFC 9728 protected resource metadata', async () => {
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/.well-known/oauth-protected-resource`)
      expect(resp.status).toBe(200)
      const body = (await resp.json()) as Record<string, unknown>
      expect(body.resource).toBe(srv.url)
      expect(body.authorization_servers).toEqual([srv.url])
    } finally {
      await srv.close()
    }
  })
})

describe('POST /otp', () => {
  async function bootstrapStep(
    srv: TestServer,
    stepType: 'otp_required' | 'password_required' = 'otp_required'
  ): Promise<void> {
    const { challenge } = pkce()
    const params = new URLSearchParams({
      client_id: 'c',
      redirect_uri: 'http://localhost/cb',
      state: 's',
      code_challenge: challenge
    })
    const getResp = await fetch(`${srv.url}/authorize?${params.toString()}`)
    const nonce = extractNonce(await getResp.text())
    const postResp = await fetch(`${srv.url}/authorize?nonce=${nonce}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: 'k' })
    })
    const body = (await postResp.json()) as Record<string, unknown>
    expect((body.next_step as Record<string, string>).type).toBe(stepType)
  }

  it('rejects /otp submission when no step is active', async () => {
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp_code: '12345' })
      })
      expect(resp.status).toBe(400)
      expect(((await resp.json()) as Record<string, string>).error).toBe('invalid_request')
    } finally {
      await srv.close()
    }
  })

  it('completes flow when step callback returns null', async () => {
    const received: Record<string, string>[] = []
    const srv = await startApp({
      onCredentialsSaved: () => ({ type: 'otp_required', field: 'otp_code' }),
      onStepSubmitted: (data) => {
        received.push(data)
        return null
      }
    })
    try {
      await bootstrapStep(srv)
      const resp = await fetch(`${srv.url}/otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp_code: '12345' })
      })
      expect(resp.status).toBe(200)
      expect(await resp.json()).toEqual({ ok: true })
      expect(received).toEqual([{ otp_code: '12345' }])

      // Subsequent call must be rejected (session cleared).
      const resp2 = await fetch(`${srv.url}/otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp_code: '12345' })
      })
      expect(resp2.status).toBe(400)
    } finally {
      await srv.close()
    }
  })

  it('chains otp_required -> password_required', async () => {
    let call = 0
    const srv = await startApp({
      onCredentialsSaved: () => ({ type: 'otp_required', field: 'otp_code' }),
      onStepSubmitted: () => {
        call += 1
        if (call === 1) return { type: 'password_required', field: 'password', text: '2FA' }
        return null
      }
    })
    try {
      await bootstrapStep(srv)

      const step1 = await fetch(`${srv.url}/otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp_code: '12345' })
      })
      const body1 = (await step1.json()) as Record<string, unknown>
      expect(body1.ok).toBe(true)
      expect((body1.next_step as Record<string, string>).type).toBe('password_required')

      const step2 = await fetch(`${srv.url}/otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'hunter2' })
      })
      expect(await step2.json()).toEqual({ ok: true })
    } finally {
      await srv.close()
    }
  })

  it('keeps pending session when callback returns {type:"error"} and allows retry', async () => {
    let call = 0
    const srv = await startApp({
      onCredentialsSaved: () => ({ type: 'otp_required', field: 'otp_code' }),
      onStepSubmitted: () => {
        call += 1
        if (call === 1) return { type: 'error', text: 'Wrong code' }
        return null
      }
    })
    try {
      await bootstrapStep(srv)

      const fail = await fetch(`${srv.url}/otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp_code: 'bad' })
      })
      expect(fail.status).toBe(200)
      expect(await fail.json()).toEqual({ ok: false, error: 'Wrong code' })

      // Retry succeeds -- session was preserved.
      const ok = await fetch(`${srv.url}/otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp_code: 'good' })
      })
      expect(ok.status).toBe(200)
      expect(await ok.json()).toEqual({ ok: true })
    } finally {
      await srv.close()
    }
  })

  it('clears session and returns 400 after exceeding attempt limit', async () => {
    const srv = await startApp({
      onCredentialsSaved: () => ({ type: 'otp_required', field: 'otp_code' }),
      onStepSubmitted: () => ({ type: 'error', text: 'Nope' })
    })
    try {
      await bootstrapStep(srv)
      // 5 attempts consume the quota, all returning {ok:false}.
      for (let i = 0; i < 5; i++) {
        const r = await fetch(`${srv.url}/otp`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ otp_code: 'x' })
        })
        expect(r.status).toBe(200)
        expect(((await r.json()) as Record<string, unknown>).ok).toBe(false)
      }
      // 6th attempt trips the limit -> 400.
      const sixth = await fetch(`${srv.url}/otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp_code: 'x' })
      })
      expect(sixth.status).toBe(400)
      const body = (await sixth.json()) as Record<string, string>
      expect(body.error_description).toBe('Too many attempts')
    } finally {
      await srv.close()
    }
  })

  it('supports async step callbacks', async () => {
    const srv = await startApp({
      onCredentialsSaved: async () => {
        await new Promise((r) => setTimeout(r, 1))
        return { type: 'otp_required', field: 'otp_code' }
      },
      onStepSubmitted: async () => {
        await new Promise((r) => setTimeout(r, 1))
        return null
      }
    })
    try {
      await bootstrapStep(srv)
      const resp = await fetch(`${srv.url}/otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp_code: '12345' })
      })
      expect(resp.status).toBe(200)
      expect(await resp.json()).toEqual({ ok: true })
    } finally {
      await srv.close()
    }
  })
})

describe('customCredentialFormHtml hook', () => {
  async function startAppWithCustom(
    customCredentialFormHtml: Parameters<typeof createLocalOAuthApp>[0]['customCredentialFormHtml']
  ): Promise<TestServer> {
    const jwtIssuer = new JWTIssuer('test-server', tempKeysDir)
    const app = await createLocalOAuthApp({
      serverName: 'test-server',
      relaySchema: SCHEMA,
      jwtIssuer,
      customCredentialFormHtml
    })
    const server: Server = createServer(app.handler)
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address() as AddressInfo
    return {
      url: `http://127.0.0.1:${addr.port}`,
      app,
      close: () => new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())))
    }
  }

  function _defaultAuthorizeParams(): URLSearchParams {
    const { challenge } = pkce()
    return new URLSearchParams({
      client_id: 'c',
      redirect_uri: 'http://x/cb',
      state: 's',
      code_challenge: challenge,
      code_challenge_method: 'S256'
    })
  }

  it('uses custom HTML when customCredentialFormHtml provided', async () => {
    const customRenderer = (_schema: RelayConfigSchema, opts: { submitUrl: string }): string =>
      `<!DOCTYPE html><html><body><h1>Custom</h1><form action="${opts.submitUrl}"></form></body></html>`

    const srv = await startAppWithCustom(customRenderer)
    try {
      const params = _defaultAuthorizeParams()
      const resp = await fetch(`${srv.url}/authorize?${params.toString()}`)
      expect(resp.status).toBe(200)
      const html = await resp.text()
      expect(html).toContain('<h1>Custom</h1>')
      expect(html).not.toContain('Enter your credentials')
      expect(html).toContain('nonce=')
    } finally {
      await srv.close()
    }
  })

  it('uses default HTML when custom not provided', async () => {
    const srv = await startAppWithCustom(undefined)
    try {
      const params = _defaultAuthorizeParams()
      const resp = await fetch(`${srv.url}/authorize?${params.toString()}`)
      expect(resp.status).toBe(200)
      const html = await resp.text()
      expect(html).toContain('Enter your credentials')
    } finally {
      await srv.close()
    }
  })

  it('passes schema and submitUrl to the custom renderer', async () => {
    const captured: { schema?: RelayConfigSchema; submitUrl?: string } = {}
    const customRenderer = (schema: RelayConfigSchema, opts: { submitUrl: string }): string => {
      captured.schema = schema
      captured.submitUrl = opts.submitUrl
      return '<html></html>'
    }

    const srv = await startAppWithCustom(customRenderer)
    try {
      const params = _defaultAuthorizeParams()
      const resp = await fetch(`${srv.url}/authorize?${params.toString()}`)
      expect(resp.status).toBe(200)
      expect(captured.schema).toEqual(SCHEMA)
      expect(captured.submitUrl).toContain('/authorize?nonce=')
    } finally {
      await srv.close()
    }
  })
})

describe('PUBLIC_URL env override', () => {
  const originalPublicUrl = process.env.PUBLIC_URL

  afterEach(() => {
    if (originalPublicUrl === undefined) {
      delete process.env.PUBLIC_URL
    } else {
      process.env.PUBLIC_URL = originalPublicUrl
    }
  })

  it('uses PUBLIC_URL as issuer in RFC 8414 metadata instead of request scheme', async () => {
    process.env.PUBLIC_URL = 'https://example.n24q02m.com'
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/.well-known/oauth-authorization-server`)
      expect(resp.status).toBe(200)
      const body = (await resp.json()) as Record<string, unknown>
      expect(body.issuer).toBe('https://example.n24q02m.com')
      expect(body.authorization_endpoint).toBe('https://example.n24q02m.com/authorize')
      expect(body.token_endpoint).toBe('https://example.n24q02m.com/token')
    } finally {
      await srv.close()
    }
  })

  it('uses PUBLIC_URL in RFC 9728 protected resource metadata', async () => {
    process.env.PUBLIC_URL = 'https://example.n24q02m.com'
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/.well-known/oauth-protected-resource`)
      expect(resp.status).toBe(200)
      const body = (await resp.json()) as Record<string, unknown>
      expect(body.resource).toBe('https://example.n24q02m.com')
      expect(body.authorization_servers).toEqual(['https://example.n24q02m.com'])
    } finally {
      await srv.close()
    }
  })

  it('strips trailing slashes from PUBLIC_URL', async () => {
    process.env.PUBLIC_URL = 'https://example.n24q02m.com///'
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/.well-known/oauth-authorization-server`)
      const body = (await resp.json()) as Record<string, unknown>
      expect(body.issuer).toBe('https://example.n24q02m.com')
    } finally {
      await srv.close()
    }
  })

  it('falls back to request-derived URL when PUBLIC_URL is empty', async () => {
    process.env.PUBLIC_URL = ''
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/.well-known/oauth-authorization-server`)
      const body = (await resp.json()) as Record<string, unknown>
      expect(body.issuer).toBe(srv.url)
    } finally {
      await srv.close()
    }
  })
})

describe('GET /setup-status', () => {
  it('reports gdrive=idle by default and complete after markSetupComplete', async () => {
    const srv = await startApp()
    try {
      const r1 = await fetch(`${srv.url}/setup-status`)
      expect(await r1.json()).toEqual({ gdrive: 'idle' })
      srv.app.markSetupComplete()
      const r2 = await fetch(`${srv.url}/setup-status`)
      expect(await r2.json()).toEqual({ gdrive: 'complete' })
    } finally {
      await srv.close()
    }
  })

  it('reports error:<message> after markSetupFailed', async () => {
    const srv = await startApp()
    try {
      srv.app.markSetupFailed('gdrive', 'invalid_grant')
      const resp = await fetch(`${srv.url}/setup-status`)
      expect(await resp.json()).toEqual({ gdrive: 'error:invalid_grant' })
    } finally {
      await srv.close()
    }
  })

  it('collapses whitespace in multi-line error messages', async () => {
    const srv = await startApp()
    try {
      srv.app.markSetupFailed('gdrive', 'Google returned\n  expired_token\t\tretry later')
      const resp = await fetch(`${srv.url}/setup-status`)
      expect(await resp.json()).toEqual({ gdrive: 'error:Google returned expired_token retry later' })
    } finally {
      await srv.close()
    }
  })

  it('defaults to gdrive key and unknown error', async () => {
    const srv = await startApp()
    try {
      srv.app.markSetupFailed()
      const resp = await fetch(`${srv.url}/setup-status`)
      expect(await resp.json()).toEqual({ gdrive: 'error:unknown error' })
    } finally {
      await srv.close()
    }
  })

  it('empty message falls back to unknown error', async () => {
    const srv = await startApp()
    try {
      srv.app.markSetupFailed('gdrive', '')
      const resp = await fetch(`${srv.url}/setup-status`)
      expect(await resp.json()).toEqual({ gdrive: 'error:unknown error' })
    } finally {
      await srv.close()
    }
  })

  // Regression: 2026-04-24 better-email-mcp bug. A prior submit's
  // background poll flipped setupStatus["outlook"] to "complete", but the
  // key lived in a module-scoped map and survived the next form submit.
  // The second submit rendered a fresh oauth_device_code UI, started the
  // 3-second /setup-status poll, and saw the stale "complete" on the
  // first hit — the user saw the device code flash and then the app
  // redirected before they ever approved the new code. Each POST
  // /authorize must reset all existing keys back to "idle".
  it('resets stale setupStatus entries on each POST /authorize submit', async () => {
    const srv = await startApp({
      onCredentialsSaved: () => null
    })
    try {
      srv.app.markSetupComplete('outlook')
      const stale = await fetch(`${srv.url}/setup-status`)
      expect(await stale.json()).toEqual({ gdrive: 'idle', outlook: 'complete' })

      const { challenge } = pkce()
      const params = new URLSearchParams({
        client_id: 'test-client',
        redirect_uri: 'http://localhost:5555/callback',
        state: 'xyz',
        code_challenge: challenge,
        code_challenge_method: 'S256'
      })
      const getResp = await fetch(`${srv.url}/authorize?${params.toString()}`)
      const nonce = extractNonce(await getResp.text())
      await fetch(`${srv.url}/authorize?nonce=${nonce}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: 'sk-second-submit' })
      })

      const fresh = await fetch(`${srv.url}/setup-status`)
      expect(await fresh.json()).toEqual({ gdrive: 'idle', outlook: 'idle' })
    } finally {
      await srv.close()
    }
  })
})

// ---------------------------------------------------------------------------
// Root bootstrap + callback-done UX
// ---------------------------------------------------------------------------

describe('GET /', () => {
  it('returns 302 with /authorize Location containing all 4 PKCE params', async () => {
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/`, { redirect: 'manual' })
      expect(resp.status).toBe(302)
      const location = resp.headers.get('location') as string
      expect(location).toBeTruthy()
      expect(location.startsWith('/authorize?')).toBe(true)

      // Parse query; relative Location uses same-origin.
      const params = new URLSearchParams(location.replace(/^\/authorize\?/, ''))
      expect(params.get('client_id')).toBe('local-browser')
      expect(params.get('code_challenge_method')).toBe('S256')
      const state = params.get('state') as string
      expect(state).toBeTruthy()
      expect(state.length).toBeGreaterThanOrEqual(16)
      const challenge = params.get('code_challenge') as string
      // base64url S256 output: 43 chars, no padding.
      expect(challenge).toHaveLength(43)
      expect(challenge.includes('=')).toBe(false)
      expect(params.get('redirect_uri')).toContain('/callback-done')
    } finally {
      await srv.close()
    }
  })

  it('following redirect renders credential form', async () => {
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/`, { redirect: 'follow' })
      expect(resp.status).toBe(200)
      expect(resp.headers.get('content-type')).toContain('text/html')
      const body = await resp.text()
      expect(body).toContain('Enter your credentials')
      expect(body).toMatch(/nonce=[A-Za-z0-9_-]+/)
    } finally {
      await srv.close()
    }
  })

  it('each request generates fresh PKCE (no reuse)', async () => {
    const srv = await startApp()
    try {
      const r1 = await fetch(`${srv.url}/`, { redirect: 'manual' })
      const r2 = await fetch(`${srv.url}/`, { redirect: 'manual' })
      expect(r1.status).toBe(302)
      expect(r2.status).toBe(302)
      const loc1 = r1.headers.get('location') as string
      const loc2 = r2.headers.get('location') as string
      const p1 = new URLSearchParams(loc1.replace(/^\/authorize\?/, ''))
      const p2 = new URLSearchParams(loc2.replace(/^\/authorize\?/, ''))
      expect(p1.get('state')).not.toBe(p2.get('state'))
      expect(p1.get('code_challenge')).not.toBe(p2.get('code_challenge'))
    } finally {
      await srv.close()
    }
  })
})

describe('GET /callback-done', () => {
  it('returns friendly setup-complete page', async () => {
    const srv = await startApp()
    try {
      const resp = await fetch(`${srv.url}/callback-done`)
      expect(resp.status).toBe(200)
      expect(resp.headers.get('content-type')).toContain('text/html')
      const body = await resp.text()
      expect(body).toContain('Setup complete')
      expect(body).toContain('close this tab')
    } finally {
      await srv.close()
    }
  })
})
