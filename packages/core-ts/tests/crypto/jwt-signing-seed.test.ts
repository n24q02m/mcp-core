import { createHash, createPrivateKey } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { deriveJwtSigningSeed } from '../../src/crypto/kdf.js'

const vectors = JSON.parse(readFileSync(join(__dirname, '..', 'fixtures', 'crypto-vectors.json'), 'utf-8'))

describe('deriveJwtSigningSeed', () => {
  it('returns 32 bytes', () => {
    const seed = deriveJwtSigningSeed('any-secret', 'some-server')
    expect(seed).toBeInstanceOf(Buffer)
    expect(seed.length).toBe(32)
  })

  it('is deterministic', () => {
    expect(deriveJwtSigningSeed('secret-1', 'wet-mcp')).toEqual(deriveJwtSigningSeed('secret-1', 'wet-mcp'))
  })

  it('is domain-separated by server name', () => {
    expect(deriveJwtSigningSeed('secret-1', 'wet-mcp')).not.toEqual(deriveJwtSigningSeed('secret-1', 'mnemo-mcp'))
  })

  it('is domain-separated by secret', () => {
    expect(deriveJwtSigningSeed('secret-1', 'wet-mcp')).not.toEqual(deriveJwtSigningSeed('secret-2', 'wet-mcp'))
  })

  it('matches the cross-language parity vector (okp x + kid)', () => {
    const v = vectors.jwt_signing_seed
    const seed = deriveJwtSigningSeed(v.credential_secret, v.server_name)
    // Wrap seed in RFC 8410 PKCS8 DER -> recover OKP public JWK via node:crypto.
    const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed])
    const pem = `-----BEGIN PRIVATE KEY-----\n${der.toString('base64')}\n-----END PRIVATE KEY-----\n`
    const jwk = createPrivateKey(pem).export({ format: 'jwk' }) as { x: string }
    expect(jwk.x).toBe(v.okp_x)
    const kid = createHash('sha256').update(Buffer.from(jwk.x, 'base64url')).digest('base64url').slice(0, 16)
    expect(kid).toBe(v.kid)
  })
})
