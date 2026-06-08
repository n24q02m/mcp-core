import { Buffer } from 'node:buffer'
import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import type { IncomingMessage, ServerResponse } from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createDelegatedOAuthApp } from '../../src/auth/delegated-oauth-app.js'
import { JWTIssuer } from '../../src/oauth/jwt-issuer.js'

vi.mock('node:crypto', async () => {
  const actual = await vi.importActual('node:crypto')
  return {
    ...actual,
    timingSafeEqual: vi.fn(actual.timingSafeEqual as any)
  }
})

describe('s256Verify error handling', () => {
  let tempKeysDir: string

  beforeEach(async () => {
    tempKeysDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-test-keys-'))
    process.env.PUBLIC_URL = 'http://localhost'
  })

  afterEach(async () => {
    await fs.rm(tempKeysDir, { recursive: true, force: true })
    vi.restoreAllMocks()
    delete process.env.PUBLIC_URL
  })

  it('returns false when timingSafeEqual throws', async () => {
    const { timingSafeEqual } = await import('node:crypto')

    const jwtIssuer = new JWTIssuer('test-server', tempKeysDir)
    const app = await createDelegatedOAuthApp({
      serverName: 'test-server',
      flow: 'redirect',
      upstream: {
        authorizeUrl: 'https://example.com/authorize',
        tokenUrl: 'https://example.com/token',
        clientId: 'client-id'
      },
      onTokenReceived: () => {},
      jwtIssuer
    })

    const baseUrl = 'http://localhost'

    // 1. Start session
    const authParams = new URLSearchParams({
      client_id: 'local-browser',
      redirect_uri: `${baseUrl}/callback-done`,
      state: 'state123',
      code_challenge: createHash('sha256').update('verifier123', 'ascii').digest('base64url'),
      code_challenge_method: 'S256'
    })

    const reqAuth = {
      method: 'GET',
      url: `/authorize?${authParams.toString()}`,
      headers: { host: 'localhost' },
      socket: {}
    } as IncomingMessage

    let authHeaders: any = {}
    let authBody = ''
    const resAuth = {
      writeHead: vi.fn((_status, headers) => {
        authHeaders = headers
      }),
      end: vi.fn((body) => {
        if (body) authBody = body
      }),
      setHeader: vi.fn((name, value) => {
        authHeaders[name] = value
      })
    } as unknown as ServerResponse

    await app.handler(reqAuth, resAuth)

    const location = authHeaders.Location
    if (!location) {
      throw new Error(
        `Location header not found in /authorize response. Headers: ${JSON.stringify(authHeaders)}. Body: ${authBody}`
      )
    }

    const nonce = new URL(location).searchParams.get('state')

    // 2. Callback from upstream
    const reqCb = {
      method: 'GET',
      url: `/callback?code=up-code&state=${nonce}`,
      headers: { host: 'localhost' },
      socket: {}
    } as IncomingMessage

    let cbHeaders: any = {}
    const resCb = {
      writeHead: vi.fn((_status, headers) => {
        cbHeaders = headers
      }),
      end: vi.fn(),
      setHeader: vi.fn((name, value) => {
        cbHeaders[name] = value
      })
    } as unknown as ServerResponse

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ access_token: 'up-at' })
    }) as any

    await app.handler(reqCb, resCb)

    const finalLocation = cbHeaders.Location
    if (!finalLocation) {
      throw new Error(`Location header not found in /callback response. Headers: ${JSON.stringify(cbHeaders)}`)
    }
    const code = new URL(finalLocation, baseUrl).searchParams.get('code')

    // NOW mock it to throw
    vi.mocked(timingSafeEqual).mockImplementation(() => {
      throw new Error('crypto error')
    })

    // 3. Token exchange (triggers s256Verify)
    const tokenParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code!,
      code_verifier: 'verifier123'
    })

    const reqTok = {
      method: 'POST',
      url: '/token',
      headers: {
        host: 'localhost',
        'content-type': 'application/x-www-form-urlencoded'
      },
      socket: {},
      on: (event: string, cb: any) => {
        if (event === 'data') cb(Buffer.from(tokenParams.toString()))
        if (event === 'end') cb()
        return reqTok
      }
    } as unknown as IncomingMessage

    let responseBody = ''
    const resTok = {
      writeHead: vi.fn(),
      end: vi.fn((data: string) => {
        responseBody = data
      }),
      setHeader: vi.fn()
    } as unknown as ServerResponse

    await app.handler(reqTok, resTok)

    expect(resTok.writeHead).toHaveBeenCalledWith(400, expect.any(Object))
    expect(JSON.parse(responseBody)).toEqual({ error: 'invalid_grant' })
    expect(timingSafeEqual).toHaveBeenCalled()
  })
})
