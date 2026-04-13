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
  } = {}
): Promise<TestServer> {
  const jwtIssuer = new JWTIssuer('test-server', tempKeysDir)
  const app = await createLocalOAuthApp({
    serverName: 'test-server',
    relaySchema: SCHEMA,
    jwtIssuer,
    onCredentialsSaved: options.onCredentialsSaved,
    onStepSubmitted: options.onStepSubmitted
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
      const payload = await srv.app.jwtIssuer.verifyAccessToken(body.access_token as string)
      expect(payload.sub).toBe('local-user')
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
})
