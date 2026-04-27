import { createHash } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { JWTIssuer } from '../../src/oauth/jwt-issuer.js'
import { InMemoryAuthCache, OAuthProvider, type PreAuthSession } from '../../src/oauth/provider.js'
import * as relayClient from '../../src/relay/client.js'
import type { RelayConfigSchema } from '../../src/schema/types.js'

vi.mock('../../src/relay/client.js', () => ({
  createSession: vi.fn(),
  pollForResult: vi.fn()
}))

// Bun's vitest shim hoists ``vi.mock`` calls beyond the current file. The
// mock here used to omit ``init()``, which broke ``tests/transport/oauth-
// middleware.test.ts`` (suite #2026-04-26 audit). Mirror the real surface
// so cross-file leakage is harmless: ``init()`` resolves, ``issueAccessToken``
// is the mock surface that this file actually inspects.
vi.mock('../../src/oauth/jwt-issuer.js', () => {
  return {
    JWTIssuer: vi.fn().mockImplementation(function (this: any) {
      this.init = vi.fn().mockResolvedValue(undefined)
      this.issueAccessToken = vi.fn()
      this.getJwks = vi.fn().mockResolvedValue({ keys: [] })
      this.verifyAccessToken = vi.fn()
    })
  }
})

describe('InMemoryAuthCache', () => {
  it('should save and retrieve a session', () => {
    const cache = new InMemoryAuthCache()
    const session: PreAuthSession = {
      sessionId: 'sess-1',
      clientId: 'client-1',
      redirectUri: 'https://app.example.com/callback',
      state: 'state-1',
      codeChallenge: 'challenge-1',
      codeChallengeMethod: 'S256',
      keyPairJwk: { kty: 'EC', crv: 'P-256', x: '...', y: '...', d: '...' },
      passphrase: 'pass-1',
      expiresAt: Math.floor(Date.now() / 1000) + 600
    }
    cache.save(session)
    const retrieved = cache.getAndDelete('sess-1')
    expect(retrieved).toEqual(session)
  })

  it('should delete session after retrieval', () => {
    const cache = new InMemoryAuthCache()
    const session: PreAuthSession = {
      sessionId: 'sess-1',
      clientId: 'client-1',
      redirectUri: 'https://app.example.com/callback',
      state: 'state-1',
      codeChallenge: 'challenge-1',
      codeChallengeMethod: 'S256',
      keyPairJwk: { kty: 'EC', crv: 'P-256', x: '...', y: '...', d: '...' },
      passphrase: 'pass-1',
      expiresAt: Math.floor(Date.now() / 1000) + 600
    }
    cache.save(session)
    cache.getAndDelete('sess-1')
    expect(cache.getAndDelete('sess-1')).toBeNull()
  })

  it('should not return expired sessions', () => {
    const cache = new InMemoryAuthCache()
    const session: PreAuthSession = {
      sessionId: 'sess-1',
      clientId: 'client-1',
      redirectUri: 'https://app.example.com/callback',
      state: 'state-1',
      codeChallenge: 'challenge-1',
      codeChallengeMethod: 'S256',
      keyPairJwk: { kty: 'EC', crv: 'P-256', x: '...', y: '...', d: '...' },
      passphrase: 'pass-1',
      expiresAt: Math.floor(Date.now() / 1000) - 1 // expired
    }

    // We need to bypass the cleanup in save() to test expiration in getAndDelete()
    const map = (cache as any).cache as Map<string, PreAuthSession>
    map.set('sess-1', session)

    expect(map.has('sess-1')).toBe(true)
    expect(cache.getAndDelete('sess-1')).toBeNull()

    // Verify it was deleted even though it was expired
    expect(map.has('sess-1')).toBe(false)
  })

  it('should cleanup expired entries on save', () => {
    const cache = new InMemoryAuthCache()
    const expired: PreAuthSession = {
      sessionId: 'expired',
      clientId: 'client-1',
      redirectUri: 'https://app.example.com/callback',
      state: 'state-1',
      codeChallenge: 'challenge-1',
      codeChallengeMethod: 'S256',
      keyPairJwk: { kty: 'EC', crv: 'P-256', x: '...', y: '...', d: '...' },
      passphrase: 'pass-1',
      expiresAt: Math.floor(Date.now() / 1000) - 1
    }
    const valid: PreAuthSession = {
      sessionId: 'valid',
      clientId: 'client-1',
      redirectUri: 'https://app.example.com/callback',
      state: 'state-1',
      codeChallenge: 'challenge-1',
      codeChallengeMethod: 'S256',
      keyPairJwk: { kty: 'EC', crv: 'P-256', x: '...', y: '...', d: '...' },
      passphrase: 'pass-1',
      expiresAt: Math.floor(Date.now() / 1000) + 600
    }

    // Manually set expired session to avoid immediate cleanup on save
    const map = (cache as any).cache as Map<string, PreAuthSession>
    map.set('expired', expired)

    cache.save(valid)

    expect(map.has('expired')).toBe(false)
    expect(cache.getAndDelete('valid')).toEqual(valid)
  })
})

describe('OAuthProvider', () => {
  let provider: OAuthProvider
  let mockJwtIssuer: JWTIssuer
  const relaySchema: RelayConfigSchema = {
    server: 'test-server',
    displayName: 'Test Server'
  }

  beforeEach(() => {
    mockJwtIssuer = new JWTIssuer('test-server')
    provider = new OAuthProvider({
      serverName: 'test-server',
      relayBaseUrl: 'https://relay.example.com',
      relaySchema,
      jwtIssuer: mockJwtIssuer
    })
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  it('should use custom cache if provided', () => {
    const customCache = {
      save: vi.fn(),
      getAndDelete: vi.fn()
    }
    const providerWithCache = new OAuthProvider({
      serverName: 'test-server',
      relayBaseUrl: 'https://relay.example.com',
      relaySchema,
      jwtIssuer: mockJwtIssuer,
      cache: customCache
    })
    expect((providerWithCache as any).cache).toBe(customCache)
  })

  describe('createAuthorizeRedirect', () => {
    it('should create a relay session and save pre-auth session', async () => {
      const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
        'deriveKey',
        'deriveBits'
      ])

      const mockSession = {
        sessionId: 'sess-123',
        keyPair,
        passphrase: 'test-passphrase',
        relayUrl: 'https://relay.example.com/authorize?s=sess-123'
      }

      vi.mocked(relayClient.createSession).mockResolvedValue(mockSession)

      const url = await provider.createAuthorizeRedirect(
        'client-1',
        'https://app.example.com/callback',
        'state-123',
        'challenge-456',
        'S256'
      )

      expect(url).toBe('https://relay.example.com/authorize?s=sess-123')
      expect(relayClient.createSession).toHaveBeenCalledWith('https://relay.example.com', 'test-server', relaySchema)
    })
  })

  describe('exchangeCode', () => {
    const codeVerifier = 'verifier-123'
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')

    it('should exchange code for access token with S256 PKCE', async () => {
      const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
        'deriveKey',
        'deriveBits'
      ])
      const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)

      const cache = (provider as any).cache as InMemoryAuthCache
      cache.save({
        sessionId: 'code-123',
        clientId: 'client-1',
        redirectUri: 'https://app.example.com/callback',
        state: 'state-1',
        codeChallenge,
        codeChallengeMethod: 'S256',
        keyPairJwk: privateJwk,
        passphrase: 'pass-1',
        expiresAt: Math.floor(Date.now() / 1000) + 600
      })

      vi.mocked(relayClient.pollForResult).mockResolvedValue({ user_id: 'alice', other: 'data' })
      vi.mocked(mockJwtIssuer.issueAccessToken).mockResolvedValue('fake-access-token')

      const result = await provider.exchangeCode('code-123', codeVerifier, (creds) => creds.user_id)

      expect(result.accessToken).toBe('fake-access-token')
      expect(result.credentials).toEqual({ user_id: 'alice', other: 'data' })
      expect(mockJwtIssuer.issueAccessToken).toHaveBeenCalledWith('alice')
    })

    it('should exchange code for access token with plain PKCE', async () => {
      const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
        'deriveKey',
        'deriveBits'
      ])
      const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)

      const cache = (provider as any).cache as InMemoryAuthCache
      cache.save({
        sessionId: 'code-plain',
        clientId: 'client-1',
        redirectUri: 'https://app.example.com/callback',
        state: 'state-1',
        codeChallenge: 'plain-verifier',
        codeChallengeMethod: 'plain',
        keyPairJwk: privateJwk,
        passphrase: 'pass-1',
        expiresAt: Math.floor(Date.now() / 1000) + 600
      })

      vi.mocked(relayClient.pollForResult).mockResolvedValue({ user_id: 'bob' })
      vi.mocked(mockJwtIssuer.issueAccessToken).mockResolvedValue('bob-token')

      const result = await provider.exchangeCode('code-plain', 'plain-verifier', (creds) => creds.user_id)

      expect(result.accessToken).toBe('bob-token')
      expect(mockJwtIssuer.issueAccessToken).toHaveBeenCalledWith('bob')
    })

    it('should throw on S256 PKCE verification failure', async () => {
      const cache = (provider as any).cache as InMemoryAuthCache
      cache.save({
        sessionId: 'code-fail',
        clientId: 'client-1',
        redirectUri: 'https://app.example.com/callback',
        state: 'state-1',
        codeChallenge: 'wrong-challenge',
        codeChallengeMethod: 'S256',
        keyPairJwk: {},
        passphrase: 'pass-1',
        expiresAt: Math.floor(Date.now() / 1000) + 600
      })

      await expect(provider.exchangeCode('code-fail', 'some-verifier', (c) => c.id)).rejects.toThrow(
        'invalid_grant: PKCE verification failed'
      )
    })

    it('should throw on plain PKCE verification failure', async () => {
      const cache = (provider as any).cache as InMemoryAuthCache
      cache.save({
        sessionId: 'code-fail-plain',
        clientId: 'client-1',
        redirectUri: 'https://app.example.com/callback',
        state: 'state-1',
        codeChallenge: 'wrong-challenge',
        codeChallengeMethod: 'plain',
        keyPairJwk: {},
        passphrase: 'pass-1',
        expiresAt: Math.floor(Date.now() / 1000) + 600
      })

      await expect(provider.exchangeCode('code-fail-plain', 'some-verifier', (c) => c.id)).rejects.toThrow(
        'invalid_grant: PKCE plain verification failed'
      )
    })

    it('should throw on invalid/expired code', async () => {
      await expect(provider.exchangeCode('non-existent', 'verifier', (c) => c.id)).rejects.toThrow(
        'invalid_grant: Expired or invalid code'
      )
    })

    it('should throw on unsupported challenge method', async () => {
      const cache = (provider as any).cache as InMemoryAuthCache
      cache.save({
        sessionId: 'code-unsupported',
        clientId: 'client-1',
        redirectUri: 'https://app.example.com/callback',
        state: 'state-1',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'unknown',
        keyPairJwk: {},
        passphrase: 'pass-1',
        expiresAt: Math.floor(Date.now() / 1000) + 600
      })

      await expect(provider.exchangeCode('code-unsupported', 'verifier', (c) => c.id)).rejects.toThrow(
        'unsupported_challenge_method'
      )
    })

    it('should throw if userIdExtractor returns empty', async () => {
      const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
        'deriveKey',
        'deriveBits'
      ])
      const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)

      const cache = (provider as any).cache as InMemoryAuthCache
      cache.save({
        sessionId: 'code-no-user',
        clientId: 'client-1',
        redirectUri: 'https://app.example.com/callback',
        state: 'state-1',
        codeChallenge: 'plain',
        codeChallengeMethod: 'plain',
        keyPairJwk: privateJwk,
        passphrase: 'pass-1',
        expiresAt: Math.floor(Date.now() / 1000) + 600
      })

      vi.mocked(relayClient.pollForResult).mockResolvedValue({ some: 'data' })

      await expect(provider.exchangeCode('code-no-user', 'plain', () => '')).rejects.toThrow(
        'server_error: Unable to extract user_id from credentials'
      )
    })
  })

  describe('getMetadata', () => {
    it('should return correct metadata', () => {
      const metadata = provider.getMetadata('https://server.example.com')
      expect(metadata).toEqual({
        issuer: 'https://server.example.com',
        authorization_endpoint: 'https://server.example.com/authorize',
        token_endpoint: 'https://server.example.com/token',
        jwks_uri: 'https://server.example.com/.well-known/jwks.json',
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        code_challenge_methods_supported: ['S256', 'plain'],
        token_endpoint_auth_methods_supported: ['none']
      })
    })
  })
})
