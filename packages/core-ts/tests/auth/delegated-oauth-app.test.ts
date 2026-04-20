/**
 * Integration tests for the delegated OAuth 2.1 server (device_code + redirect).
 *
 * Spins up a real Node ``http.Server`` per test plus a second HTTP server
 * that stubs the upstream ``authorize`` / ``token`` / ``device_authorization``
 * endpoints.
 */

import { createHash, randomBytes } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createDelegatedOAuthApp, type DelegatedOAuthAppResult } from '../../src/auth/delegated-oauth-app.js'
import { JWTIssuer } from '../../src/oauth/jwt-issuer.js'

type UpstreamHandler = (req: IncomingMessage, res: ServerResponse, body: string) => void | Promise<void>

interface UpstreamServer {
  url: string
  close: () => Promise<void>
}

async function startUpstream(handler: UpstreamHandler): Promise<UpstreamServer> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf-8')
      Promise.resolve(handler(req, res, body)).catch(() => {
        if (!res.headersSent) {
          res.writeHead(500)
          res.end()
        }
      })
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address() as AddressInfo
  return {
    url: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())))
  }
}

interface TestServer {
  url: string
  app: DelegatedOAuthAppResult
  close: () => Promise<void>
}

async function startApp(options: {
  flow: 'device_code' | 'redirect'
  upstream: {
    tokenUrl: string
    clientId: string
    clientSecret?: string
    scopes?: string[]
    authorizeUrl?: string
    deviceAuthUrl?: string
    pollIntervalMs?: number
    callbackPath?: string
  }
  onTokenReceived: (tokens: Record<string, unknown>) => void | Promise<void>
  keysDir: string
}): Promise<TestServer> {
  const jwtIssuer = new JWTIssuer('test-delegated', options.keysDir)
  const app = await createDelegatedOAuthApp({
    serverName: 'test-delegated',
    flow: options.flow,
    upstream: options.upstream,
    onTokenReceived: options.onTokenReceived,
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

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url')
  return { verifier, challenge }
}

let tempKeysDir: string

beforeEach(() => {
  tempKeysDir = mkdtempSync(join(tmpdir(), 'mcp-core-jwt-'))
})

afterEach(() => {
  rmSync(tempKeysDir, { recursive: true, force: true })
})

describe('root bootstrap UX', () => {
  it('GET / auto-generates PKCE and redirects to /authorize (delegated redirect flow)', async () => {
    const upstream = await startUpstream(() => {})
    try {
      const srv = await startApp({
        flow: 'redirect',
        upstream: {
          tokenUrl: `${upstream.url}/token`,
          clientId: 'up-client',
          scopes: ['read'],
          authorizeUrl: `${upstream.url}/authorize`
        },
        onTokenReceived: () => {},
        keysDir: tempKeysDir
      })
      try {
        const resp = await fetch(`${srv.url}/`, { redirect: 'manual' })
        expect(resp.status).toBe(302)
        const loc = resp.headers.get('location') as string
        expect(loc.startsWith('/authorize?')).toBe(true)
        const qs = new URLSearchParams(loc.slice('/authorize?'.length))
        expect(qs.get('client_id')).toBe('local-browser')
        expect(qs.get('code_challenge_method')).toBe('S256')
        expect(qs.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{40,}$/)
        expect(qs.get('state')).toMatch(/^[A-Za-z0-9_-]+$/)
        expect(qs.get('redirect_uri')).toBe(`${srv.url}/callback-done`)
      } finally {
        await srv.close()
      }
    } finally {
      await upstream.close()
    }
  })

  it('GET /callback-done returns terminal success page', async () => {
    const upstream = await startUpstream(() => {})
    try {
      const srv = await startApp({
        flow: 'redirect',
        upstream: {
          tokenUrl: `${upstream.url}/token`,
          clientId: 'up-client',
          scopes: ['read'],
          authorizeUrl: `${upstream.url}/authorize`
        },
        onTokenReceived: () => {},
        keysDir: tempKeysDir
      })
      try {
        const resp = await fetch(`${srv.url}/callback-done`)
        expect(resp.status).toBe(200)
        expect(resp.headers.get('content-type') || '').toMatch(/text\/html/)
        const body = await resp.text()
        expect(body).toContain('Setup complete')
      } finally {
        await srv.close()
      }
    } finally {
      await upstream.close()
    }
  })
})

describe('redirect flow', () => {
  it('GET /authorize redirects to upstream with our nonce as state', async () => {
    const upstream = await startUpstream(() => {
      // Never called in this test.
    })
    try {
      const srv = await startApp({
        flow: 'redirect',
        upstream: {
          tokenUrl: `${upstream.url}/token`,
          clientId: 'up-client',
          scopes: ['read', 'write'],
          authorizeUrl: `${upstream.url}/authorize`
        },
        onTokenReceived: () => {},
        keysDir: tempKeysDir
      })
      try {
        const { challenge } = pkce()
        const params = new URLSearchParams({
          client_id: 'mcp-client',
          redirect_uri: 'http://localhost/cb',
          state: 'client-state',
          code_challenge: challenge,
          code_challenge_method: 'S256'
        })
        const resp = await fetch(`${srv.url}/authorize?${params.toString()}`, {
          redirect: 'manual'
        })
        expect(resp.status).toBe(302)
        const loc = resp.headers.get('location') as string
        expect(loc.startsWith(`${upstream.url}/authorize`)).toBe(true)
        const locUrl = new URL(loc)
        expect(locUrl.searchParams.get('client_id')).toBe('up-client')
        expect(locUrl.searchParams.get('redirect_uri')).toBe(`${srv.url}/callback`)
        expect(locUrl.searchParams.get('response_type')).toBe('code')
        expect(locUrl.searchParams.get('scope')).toBe('read write')
        expect(locUrl.searchParams.get('state')).toBeTruthy()
      } finally {
        await srv.close()
      }
    } finally {
      await upstream.close()
    }
  })

  it('GET /callback exchanges upstream code for tokens and completes PKCE', async () => {
    const received: Record<string, unknown>[] = []
    const upstream = await startUpstream((req, res, body) => {
      if (req.url === '/token') {
        const form = new URLSearchParams(body)
        expect(form.get('grant_type')).toBe('authorization_code')
        expect(form.get('code')).toBe('upstream-code')
        expect(form.get('client_id')).toBe('up-client')
        expect(form.get('client_secret')).toBe('shh')
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ access_token: 'upstream-at', refresh_token: 'upstream-rt' }))
        return
      }
      res.writeHead(404)
      res.end()
    })
    try {
      const srv = await startApp({
        flow: 'redirect',
        upstream: {
          tokenUrl: `${upstream.url}/token`,
          clientId: 'up-client',
          clientSecret: 'shh',
          authorizeUrl: `${upstream.url}/authorize`
        },
        onTokenReceived: (t) => {
          received.push(t)
        },
        keysDir: tempKeysDir
      })
      try {
        const { verifier, challenge } = pkce()
        const params = new URLSearchParams({
          client_id: 'mcp-client',
          redirect_uri: 'http://localhost/cb',
          state: 'client-state',
          code_challenge: challenge,
          code_challenge_method: 'S256'
        })
        const redirect = await fetch(`${srv.url}/authorize?${params.toString()}`, {
          redirect: 'manual'
        })
        const nonce = new URL(redirect.headers.get('location') as string).searchParams.get('state') as string

        const cb = await fetch(`${srv.url}/callback?code=upstream-code&state=${encodeURIComponent(nonce)}`, {
          redirect: 'manual'
        })
        expect(cb.status).toBe(302)
        const finalLoc = cb.headers.get('location') as string
        expect(finalLoc.startsWith('http://localhost/cb?')).toBe(true)
        expect(received).toEqual([{ access_token: 'upstream-at', refresh_token: 'upstream-rt' }])

        const code = new URL(finalLoc).searchParams.get('code') as string
        const state = new URL(finalLoc).searchParams.get('state') as string
        expect(state).toBe('client-state')

        const tok = await fetch(`${srv.url}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            code_verifier: verifier
          }).toString()
        })
        expect(tok.status).toBe(200)
        const body = (await tok.json()) as Record<string, unknown>
        expect(body.token_type).toBe('Bearer')
        const payload = await srv.app.jwtIssuer.verifyAccessToken(body.access_token as string)
        expect(payload.sub).toBe('local-user')
      } finally {
        await srv.close()
      }
    } finally {
      await upstream.close()
    }
  })

  it('GET /callback rejects invalid state with 400', async () => {
    const upstream = await startUpstream(() => {})
    try {
      const srv = await startApp({
        flow: 'redirect',
        upstream: {
          tokenUrl: `${upstream.url}/token`,
          clientId: 'up-client',
          authorizeUrl: `${upstream.url}/authorize`
        },
        onTokenReceived: () => {},
        keysDir: tempKeysDir
      })
      try {
        const resp = await fetch(`${srv.url}/callback?code=x&state=unknown`, {
          redirect: 'manual'
        })
        expect(resp.status).toBe(400)
        const body = (await resp.json()) as Record<string, string>
        expect(body.error).toBe('invalid_request')
      } finally {
        await srv.close()
      }
    } finally {
      await upstream.close()
    }
  })
})

describe('device_code flow', () => {
  it('GET /authorize renders a page with user_code + verification_url', async () => {
    const upstream = await startUpstream((req, res, _body) => {
      if (req.url === '/device') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            device_code: 'dc-abc',
            user_code: 'WXYZ-1234',
            verification_url: 'https://example.test/verify',
            interval: 60,
            expires_in: 600
          })
        )
        return
      }
      // Polling should never land here within the test window (interval=60s).
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'authorization_pending' }))
    })
    try {
      const srv = await startApp({
        flow: 'device_code',
        upstream: {
          tokenUrl: `${upstream.url}/token`,
          clientId: 'up-client',
          scopes: ['drive'],
          deviceAuthUrl: `${upstream.url}/device`
        },
        onTokenReceived: () => {},
        keysDir: tempKeysDir
      })
      try {
        const { challenge } = pkce()
        const params = new URLSearchParams({
          client_id: 'mcp-client',
          redirect_uri: 'http://localhost/cb',
          state: 'client-state',
          code_challenge: challenge,
          code_challenge_method: 'S256'
        })
        const resp = await fetch(`${srv.url}/authorize?${params.toString()}`)
        expect(resp.status).toBe(200)
        expect(resp.headers.get('content-type')).toContain('text/html')
        const html = await resp.text()
        expect(html).toContain('WXYZ-1234')
        expect(html).toContain('https://example.test/verify')
      } finally {
        await srv.close()
      }
    } finally {
      await upstream.close()
    }
  })

  it('background poll receives token and marks setup complete', async () => {
    const received: Record<string, unknown>[] = []
    let pollCount = 0
    const upstream = await startUpstream((req, res, _body) => {
      if (req.url === '/device') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            device_code: 'dc-abc',
            user_code: 'WXYZ-1234',
            verification_url: 'https://example.test/verify',
            interval: 0,
            expires_in: 600
          })
        )
        return
      }
      if (req.url === '/token') {
        pollCount += 1
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ access_token: 'granted' }))
        return
      }
      res.writeHead(404)
      res.end()
    })
    try {
      const srv = await startApp({
        flow: 'device_code',
        upstream: {
          tokenUrl: `${upstream.url}/token`,
          clientId: 'up-client',
          deviceAuthUrl: `${upstream.url}/device`
        },
        onTokenReceived: (t) => {
          received.push(t)
        },
        keysDir: tempKeysDir
      })
      try {
        const { challenge } = pkce()
        const params = new URLSearchParams({
          client_id: 'mcp-client',
          redirect_uri: 'http://localhost/cb',
          state: 'client-state',
          code_challenge: challenge,
          code_challenge_method: 'S256'
        })
        const resp = await fetch(`${srv.url}/authorize?${params.toString()}`)
        expect(resp.status).toBe(200)

        // Wait for background poll to run.
        const deadline = Date.now() + 3000
        let status = 'idle'
        while (Date.now() < deadline) {
          const r = await fetch(`${srv.url}/setup-status`)
          const j = (await r.json()) as Record<string, string>
          status = j['test-delegated']
          if (status === 'complete') break
          await new Promise((r) => setTimeout(r, 25))
        }
        expect(status).toBe('complete')
        expect(pollCount).toBeGreaterThanOrEqual(1)
        expect(received).toEqual([{ access_token: 'granted' }])
      } finally {
        await srv.close()
      }
    } finally {
      await upstream.close()
    }
  })

  it('continues polling on authorization_pending and completes on eventual grant', async () => {
    const received: Record<string, unknown>[] = []
    let pollCount = 0
    const upstream = await startUpstream((req, res, _body) => {
      if (req.url === '/device') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(
          JSON.stringify({
            device_code: 'dc-abc',
            user_code: 'PEND-0000',
            verification_url: 'https://example.test/verify',
            interval: 0,
            expires_in: 600
          })
        )
        return
      }
      if (req.url === '/token') {
        pollCount += 1
        if (pollCount < 3) {
          res.writeHead(400, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'authorization_pending' }))
          return
        }
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ access_token: 'finally' }))
        return
      }
      res.writeHead(404)
      res.end()
    })
    try {
      const srv = await startApp({
        flow: 'device_code',
        upstream: {
          tokenUrl: `${upstream.url}/token`,
          clientId: 'up-client',
          deviceAuthUrl: `${upstream.url}/device`
        },
        onTokenReceived: (t) => {
          received.push(t)
        },
        keysDir: tempKeysDir
      })
      try {
        const { challenge } = pkce()
        const params = new URLSearchParams({
          client_id: 'mcp-client',
          redirect_uri: 'http://localhost/cb',
          state: 's',
          code_challenge: challenge,
          code_challenge_method: 'S256'
        })
        await fetch(`${srv.url}/authorize?${params.toString()}`)

        const deadline = Date.now() + 3000
        let status = 'idle'
        while (Date.now() < deadline) {
          const r = await fetch(`${srv.url}/setup-status`)
          const j = (await r.json()) as Record<string, string>
          status = j['test-delegated']
          if (status === 'complete') break
          await new Promise((r) => setTimeout(r, 25))
        }
        expect(status).toBe('complete')
        expect(pollCount).toBeGreaterThanOrEqual(3)
        expect(received).toEqual([{ access_token: 'finally' }])
      } finally {
        await srv.close()
      }
    } finally {
      await upstream.close()
    }
  })
})

describe('configuration validation', () => {
  it('rejects redirect flow without authorizeUrl', async () => {
    await expect(
      createDelegatedOAuthApp({
        serverName: 'x',
        flow: 'redirect',
        upstream: { tokenUrl: 'https://example.test/token', clientId: 'x' },
        onTokenReceived: () => {}
      })
    ).rejects.toThrow(/authorizeUrl/)
  })

  it('rejects device_code flow without deviceAuthUrl', async () => {
    await expect(
      createDelegatedOAuthApp({
        serverName: 'x',
        flow: 'device_code',
        upstream: { tokenUrl: 'https://example.test/token', clientId: 'x' },
        onTokenReceived: () => {}
      })
    ).rejects.toThrow(/deviceAuthUrl/)
  })
})
