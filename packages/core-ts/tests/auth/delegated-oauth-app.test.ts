import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createDelegatedOAuthApp } from '../../src/auth/delegated-oauth-app.js'

interface TestServer {
  port: number
  close: () => Promise<void>
}

async function startTestServer(options: {
  upstream?: {
    authorizeUrl?: string
    tokenUrl?: string
    callbackPath?: string
  }
  onTokenReceived: (tokens: Record<string, unknown>) => string | undefined | Promise<string | undefined>
  keysDir: string
}): Promise<TestServer> {
  const app = await createDelegatedOAuthApp({
    serverName: 'test-server',
    flow: 'redirect',
    upstream: {
      clientId: 'client-id',
      tokenUrl: 'http://upstream.com/token',
      authorizeUrl: 'http://upstream.com/authorize',
      ...options.upstream
    },
    onTokenReceived: options.onTokenReceived
  })

  const server = createServer((req, res) => {
    const result = app.handler(req, res)
    if (result instanceof Promise) {
      result.catch(() => {
        if (!res.headersSent) {
          res.writeHead(500)
          res.end()
        }
      })
    }
  })

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo
      resolve({
        port: addr.port,
        close: () =>
          new Promise((resolveClose) => {
            server.close(() => resolveClose())
          })
      })
    })
  })
}

describe('DelegatedOAuthApp', () => {
  let keysDir: string

  beforeEach(() => {
    keysDir = `test-keys-${Math.random().toString(36).slice(2)}`
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('creates an app with a JWT issuer', async () => {
    const app = await createDelegatedOAuthApp({
      serverName: 'test',
      flow: 'redirect',
      upstream: {
        clientId: 'c',
        authorizeUrl: 'http://u.com/authorize',
        tokenUrl: 'http://u.com/token'
      },
      onTokenReceived: () => undefined
    })

    expect(app.jwtIssuer).toBeDefined()
    expect(typeof app.handler).toBe('function')
  })

  it('routes /.well-known/oauth-authorization-server', async () => {
    const onTokenReceived = vi.fn().mockReturnValue(undefined)
    const server = await startTestServer({ onTokenReceived, keysDir })

    try {
      const res = await fetch(`http://127.0.0.1:${server.port}/.well-known/oauth-authorization-server`)
      expect(res.status).toBe(200)
      const config = await res.json()
      expect(config.issuer).toBeDefined()
    } finally {
      await server.close()
    }
  })

  it('routes /authorize to upstream', async () => {
    const onTokenReceived = vi.fn().mockReturnValue(undefined)
    const server = await startTestServer({ onTokenReceived, keysDir })

    try {
      const res = await fetch(
        `http://127.0.0.1:${server.port}/authorize?response_type=code&client_id=foo&redirect_uri=http://localhost/cb&state=st&code_challenge=ch&code_challenge_method=S256`,
        { redirect: 'manual' }
      )
      expect(res.status).toBe(302)
      const location = res.headers.get('location')
      expect(location).toContain('http://upstream.com/authorize')
      expect(location).toContain('client_id=client-id')
    } finally {
      await server.close()
    }
  })
})
