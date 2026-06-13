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
    expect(payload.typ).toBe('access')
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

describe('JWTIssuer refresh tokens (issue #261)', () => {
  const serverName = 'test-server'

  it('issueRefreshToken() + verifyRefreshToken() roundtrip with typ=refresh', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()

    const token = await issuer.issueRefreshToken('user-9')
    const payload = await issuer.verifyRefreshToken(token)
    expect(payload.sub).toBe('user-9')
    expect(payload.iss).toBe(serverName)
    expect(payload.aud).toBe(serverName)
    expect(payload.typ).toBe('refresh')
  })

  it('issueRefreshToken() throws if not initialized', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await expect(issuer.issueRefreshToken('user-9')).rejects.toThrow('JWTIssuer not initialized')
  })

  it('verifyRefreshToken() throws if not initialized', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await expect(issuer.verifyRefreshToken('some-token')).rejects.toThrow('JWTIssuer not initialized')
  })

  it('refresh token has a longer lifetime than the access token', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()
    const access = await issuer.verifyAccessToken(await issuer.issueAccessToken('u'))
    const refresh = await issuer.verifyRefreshToken(await issuer.issueRefreshToken('u'))
    const accessLifetime = (access.exp as number) - (access.iat as number)
    const refreshLifetime = (refresh.exp as number) - (refresh.iat as number)
    expect(refreshLifetime).toBeGreaterThan(accessLifetime)
    expect(refreshLifetime).toBeGreaterThanOrEqual(2592000 - 5)
  })

  it('verifyAccessToken() rejects a refresh token', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()
    const refresh = await issuer.issueRefreshToken('user-9')
    await expect(issuer.verifyAccessToken(refresh)).rejects.toThrow()
  })

  it('verifyRefreshToken() rejects an access token', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()
    const access = await issuer.issueAccessToken('user-9')
    await expect(issuer.verifyRefreshToken(access)).rejects.toThrow()
  })

  it('verifyRefreshToken() rejects an expired refresh token', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()
    // Negative lifetime → already expired.
    const token = await issuer.issueRefreshToken('user-9', -10)
    await expect(issuer.verifyRefreshToken(token)).rejects.toThrow()
  })

  it('verifyAccessToken() accepts a legacy token with no typ claim (backward-compat)', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()
    // Build a token via the JWKS private key path: re-sign a payload without typ.
    const jwks = await issuer.getJwks()
    // Sign with the issuer's own access-token then strip typ by re-signing is not
    // possible without the private key, so instead verify the public contract:
    // a token issued by issueAccessToken carries typ=access and still verifies,
    // and a separately-signed no-typ token verifies too. Use a sibling issuer
    // sharing the same key dir to sign a no-typ token.
    const sibling = new JWTIssuer(serverName, tempDir)
    await sibling.init()
    const noTypToken = await new jose.SignJWT({ sub: 'legacy-user' })
      .setProtectedHeader({ alg: 'RS256', kid: jwks.keys[0].kid as string })
      .setIssuer(serverName)
      .setAudience(serverName)
      .setIssuedAt()
      .setExpirationTime('3600s')
      // biome-ignore lint/suspicious/noExplicitAny: access private key for legacy-token test
      .sign((sibling as any).privateKey)
    const payload = await issuer.verifyAccessToken(noTypToken)
    expect(payload.sub).toBe('legacy-user')
    expect(payload.typ).toBeUndefined()
  })

  it('private key is not extractable in memory', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()
    // @ts-expect-error accessing private property for testing
    const priv = issuer.privateKey as jose.CryptoKey
    expect(priv.extractable).toBe(false)
  })

  it('public key is extractable in memory (required for JWKS export)', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()
    // @ts-expect-error accessing private property for testing
    const pub = issuer.publicKey as jose.CryptoKey
    expect(pub.extractable).toBe(true)
  })
})

describe('JWTIssuer derived EdDSA mode (CREDENTIAL_SECRET set)', () => {
  const serverName = 'wet-mcp'
  const SECRET = 'test-credential-secret-value'

  it('does not write PEM files in derived mode', async () => {
    const issuer = new JWTIssuer(serverName, tempDir, SECRET)
    await issuer.init()
    expect(issuer.alg).toBe('EdDSA')
    expect(existsSync(join(tempDir, `${serverName}_private.pem`))).toBe(false)
    expect(existsSync(join(tempDir, `${serverName}_public.pem`))).toBe(false)
  })

  it('derives the same key across instances (multi-replica determinism)', async () => {
    const a = new JWTIssuer(serverName, tempDir, SECRET)
    await a.init()
    const b = new JWTIssuer(serverName, tempDir, SECRET)
    await b.init()
    const ja = await a.getJwks()
    const jb = await b.getJwks()
    expect((ja.keys[0] as { x: string }).x).toBe((jb.keys[0] as { x: string }).x)
  })

  it('getJwks emits an OKP EdDSA key with thumbprint kid matching the parity vector', async () => {
    const issuer = new JWTIssuer(serverName, tempDir, SECRET)
    await issuer.init()
    const jwks = await issuer.getJwks()
    expect(jwks.keys[0]).toMatchObject({
      kty: 'OKP',
      crv: 'Ed25519',
      use: 'sig',
      alg: 'EdDSA',
      kid: 'r71l8IICMLZykZU5',
      x: 'VGfGsMquscEDCVyGu4sNbM8DihXhYAb2c1s1EDIrAdE'
    })
  })

  it('access token roundtrip uses EdDSA + thumbprint kid', async () => {
    const issuer = new JWTIssuer(serverName, tempDir, SECRET)
    await issuer.init()
    const token = await issuer.issueAccessToken('u')
    const decodedHeader = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString())
    expect(decodedHeader.alg).toBe('EdDSA')
    expect(decodedHeader.kid).toBe('r71l8IICMLZykZU5')
    const payload = await issuer.verifyAccessToken(token)
    expect(payload.sub).toBe('u')
    expect(payload.typ).toBe('access')
  })

  it('refresh token roundtrip works in EdDSA mode', async () => {
    const issuer = new JWTIssuer(serverName, tempDir, SECRET)
    await issuer.init()
    const token = await issuer.issueRefreshToken('u')
    const payload = await issuer.verifyRefreshToken(token)
    expect(payload.typ).toBe('refresh')
  })

  it('verifyAccessToken rejects a refresh token in EdDSA mode', async () => {
    const issuer = new JWTIssuer(serverName, tempDir, SECRET)
    await issuer.init()
    const refresh = await issuer.issueRefreshToken('u')
    await expect(issuer.verifyAccessToken(refresh)).rejects.toThrow()
  })
})

describe('JWTIssuer local RSA mode unchanged (no CREDENTIAL_SECRET)', () => {
  const serverName = 'test-server'

  it('defaults to RS256 + key-1 + on-disk RSA key', async () => {
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()
    expect(issuer.alg).toBe('RS256')
    expect(existsSync(join(tempDir, `${serverName}_private.pem`))).toBe(true)
    const jwks = await issuer.getJwks()
    expect(jwks.keys[0]).toMatchObject({ kty: 'RSA', alg: 'RS256', kid: 'key-1' })
  })
})
