import { mkdtemp, rm } from 'node:fs/promises'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createLocalOAuthApp } from '../../src/auth/local-oauth-app.js'
import { JWTIssuer } from '../../src/oauth/jwt-issuer.js'

let tempDir: string

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'mcp-test-jwks-'))
})

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true })
})

async function withServer(handler: (req: never, res: never) => Promise<void>, fn: (base: string) => Promise<void>) {
  const server = createServer((req, res) => {
    handler(req as never, res as never).catch(() => res.end())
  })
  await new Promise<void>((resolve) => server.listen(0, resolve))
  const { port } = server.address() as AddressInfo
  try {
    await fn(`http://127.0.0.1:${port}`)
  } finally {
    server.close()
  }
}

// LocalOAuthAppOptions has no jwtKeysDir field; the keys-dir default lives in
// JWTIssuer. Inject a pre-built EdDSA issuer (tmp dir, credential secret set) so
// the JWKS endpoint serves an OKP key without touching the real home dir.
async function buildEddsaIssuer(): Promise<JWTIssuer> {
  const issuer = new JWTIssuer('wet-mcp', tempDir, 'test-credential-secret-value')
  await issuer.init()
  return issuer
}

describe('JWKS endpoint (core-ts)', () => {
  it('serves the OKP key at /.well-known/jwks.json', async () => {
    const jwtIssuer = await buildEddsaIssuer()
    const { handler } = await createLocalOAuthApp({
      serverName: 'wet-mcp',
      relaySchema: { server: 'wet-mcp', fields: [] },
      jwtIssuer
    })
    await withServer(handler as never, async (base) => {
      const resp = await fetch(`${base}/.well-known/jwks.json`)
      expect(resp.status).toBe(200)
      const body = await resp.json()
      expect(body).toEqual(await jwtIssuer.getJwks())
      expect(body.keys[0].kty).toBe('OKP')
      expect(body.keys[0].alg).toBe('EdDSA')
    })
  })

  it('advertises jwks_uri in RFC 8414 metadata', async () => {
    const jwtIssuer = await buildEddsaIssuer()
    const { handler } = await createLocalOAuthApp({
      serverName: 'wet-mcp',
      relaySchema: { server: 'wet-mcp', fields: [] },
      jwtIssuer
    })
    await withServer(handler as never, async (base) => {
      const resp = await fetch(`${base}/.well-known/oauth-authorization-server`)
      const meta = await resp.json()
      expect(meta.jwks_uri).toMatch(/\/\.well-known\/jwks\.json$/)
    })
  })
})
