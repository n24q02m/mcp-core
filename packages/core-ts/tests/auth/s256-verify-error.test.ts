import { createHash, randomBytes } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createDelegatedOAuthApp, type DelegatedOAuthAppResult } from '../../src/auth/delegated-oauth-app.js'
import { JWTIssuer } from '../../src/oauth/jwt-issuer.js'

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>()
  return {
    ...actual,
    timingSafeEqual: vi.fn().mockImplementation(() => {
      throw new Error('Forced timingSafeEqual error')
    })
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

async function startApp(options: {
  flow: 'device_code' | 'redirect'
  upstream: {
    tokenUrl: string
    clientId: string
    clientSecret?: string
    authorizeUrl?: string
  }
  onTokenReceived: (tokens: Record<string, unknown>) => void
  keysDir: string
}): Promise<TestServer> {
  const jwtIssuer = new JWTIssuer('test-delegated-error', options.keysDir)
  const app = await createDelegatedOAuthApp({
    serverName: 'test-delegated-error',
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
  tempKeysDir = mkdtempSync(join(tmpdir(), 'mcp-core-jwt-error-'))
})

afterEach(() => {
  rmSync(tempKeysDir, { recursive: true, force: true })
  vi.restoreAllMocks()
})

describe('s256Verify error handling', () => {
  it('returns 400 when timingSafeEqual throws an error', async () => {
    const upstream = await startUpstream((req, res) => {
      if (req.url === '/token') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ access_token: 'upstream-at' }))
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
          clientId: 'up',
          clientSecret: 's',
          authorizeUrl: `${upstream.url}/authorize`
        },
        onTokenReceived: () => {},
        keysDir: tempKeysDir
      })

      try {
        const { verifier, challenge } = pkce()
        const params = new URLSearchParams({
          client_id: 'mcp',
          redirect_uri: 'http://localhost/cb',
          state: 'st',
          code_challenge: challenge,
          code_challenge_method: 'S256'
        })

        // 1. Start authorize flow
        const redirect = await fetch(`${srv.url}/authorize?${params.toString()}`, { redirect: 'manual' })
        const location = redirect.headers.get('location') as string
        const nonce = new URL(location).searchParams.get('state') as string

        // 2. Mock callback from upstream
        const cb = await fetch(`${srv.url}/callback?code=up-code&state=${encodeURIComponent(nonce)}`, {
          redirect: 'manual'
        })
        const finalLoc = cb.headers.get('location') as string
        const code = new URL(finalLoc).searchParams.get('code') as string

        // 3. Exchange code for token. This will trigger s256Verify.
        // We expect timingSafeEqual to throw, and s256Verify to catch it and return false.
        // Resulting in 400 invalid_grant.
        const tok = await fetch(`${srv.url}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            code_verifier: verifier
          }).toString()
        })

        expect(tok.status).toBe(400)
        const body = (await tok.json()) as { error?: string }
        expect(body.error).toBe('invalid_grant')

        // Verify mock was indeed called
        const { timingSafeEqual: timingSafeEqualMock } = await import('node:crypto')
        expect(timingSafeEqualMock).toHaveBeenCalled()
      } finally {
        await srv.close()
      }
    } finally {
      await upstream.close()
    }
  })
})
