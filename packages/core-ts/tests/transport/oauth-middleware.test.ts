import { mkdtempSync, rmSync } from 'node:fs'
import { IncomingMessage, ServerResponse } from 'node:http'
import { Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { JWTIssuer } from '../../src/oauth/jwt-issuer.js'
import { OAuthMiddleware } from '../../src/transport/oauth-middleware.js'

function makeRequest(headers: Record<string, string> = {}): IncomingMessage {
  const req = new IncomingMessage(new Socket())
  Object.assign(req.headers, headers)
  return req
}

function makeResponse(): {
  res: ServerResponse
  getStatus: () => number
  getHeader: (name: string) => string | undefined
  getBody: () => string
} {
  const req = new IncomingMessage(new Socket())
  const res = new ServerResponse(req)
  const chunks: Buffer[] = []
  const sentHeaders: Record<string, string> = {}
  let sentStatus = 200

  const origWriteHead = res.writeHead.bind(res)
  // @ts-expect-error override for test capture
  res.writeHead = (status: number, headers?: Record<string, string | string[]>) => {
    sentStatus = status
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        sentHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v)
      }
    }
    return origWriteHead(status, headers as Record<string, string>)
  }

  const origEnd = res.end.bind(res)
  res.end = ((chunk?: unknown) => {
    if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)))
    return origEnd(chunk as string | undefined)
  }) as typeof res.end

  return {
    res,
    getStatus: () => sentStatus,
    getHeader: (name: string) => sentHeaders[name.toLowerCase()],
    getBody: () => Buffer.concat(chunks).toString('utf-8')
  }
}

describe('OAuthMiddleware', () => {
  const keysDir = mkdtempSync(join(tmpdir(), 'mcp-core-oauth-test-'))
  let issuer: JWTIssuer
  let middleware: OAuthMiddleware

  beforeAll(async () => {
    issuer = new JWTIssuer('test-server', keysDir)
    await issuer.init()
    middleware = new OAuthMiddleware({
      jwtIssuer: issuer,
      resourceMetadataUrl: 'http://127.0.0.1:9999/.well-known/oauth-protected-resource'
    })
  })

  afterAll(() => {
    rmSync(keysDir, { recursive: true, force: true })
  })

  it('returns 401 with WWW-Authenticate when no Authorization header', async () => {
    const req = makeRequest()
    const { res, getStatus, getHeader } = makeResponse()
    const ok = await middleware.validate(req, res)
    expect(ok).toBe(false)
    expect(getStatus()).toBe(401)
    expect(getHeader('WWW-Authenticate')).toContain('resource_metadata=')
  })

  it('returns 401 with error="invalid_token" when token is garbage', async () => {
    const req = makeRequest({ authorization: 'Bearer not-a-valid-jwt' })
    const { res, getStatus, getHeader } = makeResponse()
    const ok = await middleware.validate(req, res)
    expect(ok).toBe(false)
    expect(getStatus()).toBe(401)
    expect(getHeader('WWW-Authenticate')).toContain('error="invalid_token"')
  })

  it('returns 401 when Authorization header has wrong scheme', async () => {
    const req = makeRequest({ authorization: 'Basic dXNlcjpwYXNz' })
    const { res, getStatus } = makeResponse()
    const ok = await middleware.validate(req, res)
    expect(ok).toBe(false)
    expect(getStatus()).toBe(401)
  })

  it('attaches claims to req.user and returns true on valid token', async () => {
    const token = await issuer.issueAccessToken('user-123')
    const req = makeRequest({ authorization: `Bearer ${token}` })
    const { res } = makeResponse()
    const ok = await middleware.validate(req, res)
    expect(ok).toBe(true)
    const user = (req as IncomingMessage & { user?: Record<string, unknown> }).user
    expect(user).toBeDefined()
    expect(user?.sub).toBe('user-123')
  })

  it('accepts lowercase bearer scheme per RFC 6750', async () => {
    const token = await issuer.issueAccessToken('user-456')
    const req = makeRequest({ authorization: `bearer ${token}` })
    const { res } = makeResponse()
    const ok = await middleware.validate(req, res)
    expect(ok).toBe(true)
  })
})
