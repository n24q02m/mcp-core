import { createHash, randomBytes } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createDelegatedOAuthApp, type DelegatedOAuthAppResult } from '../../src/auth/delegated-oauth-app.js'

let shouldThrow = false

vi.mock('node:crypto', async () => {
  const actual = await vi.importActual<typeof import('node:crypto')>('node:crypto')
  return {
    ...actual,
    timingSafeEqual: (a: Buffer, b: Buffer) => {
      if (shouldThrow) {
        throw new Error('Forced timingSafeEqual failure')
      }
      return actual.timingSafeEqual(a, b)
    }
  }
})

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

async function startApp(opts: Parameters<typeof createDelegatedOAuthApp>[0]): Promise<TestServer> {
  const app = await createDelegatedOAuthApp(opts)
  const server = createServer((req, res) => {
    app.handler(req, res).catch((err) => {
      console.error('App handler error:', err)
      if (!res.headersSent) {
        res.writeHead(500)
        res.end()
      }
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address() as AddressInfo
  return {
    url: `http://127.0.0.1:${addr.port}`,
    app,
    close: async () => {
      await app.shutdown()
      return new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())))
    }
  }
}

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url')
  return { verifier, challenge }
}

describe('s256Verify coverage', () => {
  let tempKeysDir: string

  beforeEach(() => {
    tempKeysDir = mkdtempSync(join(tmpdir(), 'mcp-test-keys-'))
    shouldThrow = false
  })

  afterEach(() => {
    rmSync(tempKeysDir, { recursive: true, force: true })
  })

  it('handles timingSafeEqual exception in s256Verify', async () => {
    const upstream = await startUpstream((req, res) => {
      if (req.url?.startsWith('/token')) {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ access_token: 'up-at' }))
        return
      }
      res.writeHead(404)
      res.end()
    })

    try {
      const srv = await startApp({
        serverName: 'test-srv',
        flow: 'redirect',
        upstream: {
          tokenUrl: `${upstream.url}/token`,
          clientId: 'up-client',
          clientSecret: 'up-secret',
          authorizeUrl: `${upstream.url}/authorize`
        },
        onTokenReceived: () => 'user-123',
        keysDir: tempKeysDir
      })

      try {
        const { verifier, challenge } = pkce()

        // 1. Get nonce from /authorize
        const authParams = new URLSearchParams({
          client_id: 'mcp-client',
          redirect_uri: 'http://localhost/cb',
          state: 'client-state',
          code_challenge: challenge,
          code_challenge_method: 'S256'
        })
        const authResp = await fetch(`${srv.url}/authorize?${authParams.toString()}`, { redirect: 'manual' })
        const location = authResp.headers.get('location')
        const nonce = new URL(location!).searchParams.get('state')

        // 2. Complete callback to get local auth_code
        const cbResp = await fetch(`${srv.url}/callback?code=up-code&state=${encodeURIComponent(nonce!)}`, { redirect: 'manual' })
        const finalLoc = cbResp.headers.get('location')
        const authCode = new URL(finalLoc!).searchParams.get('code')

        // 3. Exchange code for token with forced failure
        shouldThrow = true
        const tokenResp = await fetch(`${srv.url}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: authCode!,
            code_verifier: verifier,
            client_id: 'mcp-client'
          }).toString()
        })

        expect(tokenResp.status).toBe(400)
        const body = (await tokenResp.json()) as { error: string }
        expect(body.error).toBe('invalid_grant')
      } finally {
        await srv.close()
      }
    } finally {
      await upstream.close()
    }
  })

  it('works correctly when not throwing', async () => {
    const upstream = await startUpstream((req, res) => {
      if (req.url?.startsWith('/token')) {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ access_token: 'up-at' }))
        return
      }
      res.writeHead(404)
      res.end()
    })

    try {
      const srv = await startApp({
        serverName: 'test-srv',
        flow: 'redirect',
        upstream: {
          tokenUrl: `${upstream.url}/token`,
          clientId: 'up-client',
          clientSecret: 'up-secret',
          authorizeUrl: `${upstream.url}/authorize`
        },
        onTokenReceived: () => 'user-123',
        keysDir: tempKeysDir
      })

      try {
        const { verifier, challenge } = pkce()

        // 1. Get nonce from /authorize
        const authParams = new URLSearchParams({
          client_id: 'mcp-client',
          redirect_uri: 'http://localhost/cb',
          state: 'client-state',
          code_challenge: challenge,
          code_challenge_method: 'S256'
        })
        const authResp = await fetch(`${srv.url}/authorize?${authParams.toString()}`, { redirect: 'manual' })
        const location = authResp.headers.get('location')
        const nonce = new URL(location!).searchParams.get('state')

        // 2. Complete callback to get local auth_code
        const cbResp = await fetch(`${srv.url}/callback?code=up-code&state=${encodeURIComponent(nonce!)}`, { redirect: 'manual' })
        const finalLoc = cbResp.headers.get('location')
        const authCode = new URL(finalLoc!).searchParams.get('code')

        // 3. Exchange code for token (success)
        const tokenResp = await fetch(`${srv.url}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: authCode!,
            code_verifier: verifier,
            client_id: 'mcp-client'
          }).toString()
        })

        expect(tokenResp.status).toBe(200)

        // 4. Exchange with wrong verifier (failure, but not throw)
        const tokenRespFail = await fetch(`${srv.url}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: authCode!,
            code_verifier: 'wrong-verifier',
            client_id: 'mcp-client'
          }).toString()
        })
        expect(tokenRespFail.status).toBe(400)
        const bodyFail = (await tokenRespFail.json()) as { error: string }
        expect(bodyFail.error).toBe('invalid_grant')
      } finally {
        await srv.close()
      }
    } finally {
      await upstream.close()
    }
  })
})
