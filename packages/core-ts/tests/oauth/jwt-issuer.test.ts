import { existsSync } from 'node:fs'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import * as jose from 'jose'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { JWTIssuer } from '../../src/oauth/jwt-issuer.js'

let tempDir: string

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'mcp-test-jwt-'))
})

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true })
})

describe('JWTIssuer', () => {
  const serverName = 'test-server'

  it('init() generates RSA keys if they do not exist', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()

    expect(existsSync(join(tempDir, `${serverName}_private.pem`))).toBe(true)
    expect(existsSync(join(tempDir, `${serverName}_public.pem`))).toBe(true)
  })

  it('init() loads existing keys from PEM files', async () => {
    // Generate keys first
    const { publicKey, privateKey } = await jose.generateKeyPair('RS256', {
      modulusLength: 2048,
      extractable: true
    })
    const privatePem = await jose.exportPKCS8(privateKey)
    const publicPem = await jose.exportSPKI(publicKey)

    await writeFile(join(tempDir, `${serverName}_private.pem`), privatePem)
    await writeFile(join(tempDir, `${serverName}_public.pem`), publicPem)

    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()

    // It should not throw and should be initialized
    const jwks = await issuer.getJwks()
    expect(jwks.keys).toHaveLength(1)
  })

  it('getJwks() returns a valid JWKS and throws if not initialized', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await expect(issuer.getJwks()).rejects.toThrow('JWTIssuer not initialized')

    await issuer.init()
    const jwks = await issuer.getJwks()
    expect(jwks.keys).toHaveLength(1)
    expect(jwks.keys[0]).toMatchObject({
      kid: 'key-1',
      use: 'sig',
      alg: 'RS256',
      kty: 'RSA'
    })
  })

  it('issueAccessToken() creates a valid signed JWT and throws if not initialized', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await expect(issuer.issueAccessToken('user-1')).rejects.toThrow('JWTIssuer not initialized')

    await issuer.init()
    const token = await issuer.issueAccessToken('user-1')
    expect(typeof token).toBe('string')

    // Use JWKS to verify
    const jwks = await issuer.getJwks()
    const key = await jose.importJWK(jwks.keys[0])

    const { payload, protectedHeader } = await jose.jwtVerify(token, key, {
      issuer: serverName,
      audience: serverName
    })
    expect(payload.sub).toBe('user-1')
    expect(payload.iss).toBe(serverName)
    expect(payload.aud).toBe(serverName)
    expect(protectedHeader.alg).toBe('RS256')
    expect(protectedHeader.kid).toBe('key-1')
  })

  it('verifyAccessToken() successfully verifies a valid token and returns the payload', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()

    const token = await issuer.issueAccessToken('user-1')
    const payload = await issuer.verifyAccessToken(token)

    expect(payload.sub).toBe('user-1')
  })

  it('verifyAccessToken() throws on invalid tokens', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()

    await expect(issuer.verifyAccessToken('invalid-token')).rejects.toThrow()
  })

  it('verifyAccessToken() throws if not initialized', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await expect(issuer.verifyAccessToken('some-token')).rejects.toThrow('JWTIssuer not initialized')
  })
})
