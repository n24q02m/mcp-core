import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { InMemoryAuthCache, type PreAuthSession } from '../../src/oauth/cache.js'

describe('InMemoryAuthCache', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  const createSession = (overrides: Partial<PreAuthSession> = {}): PreAuthSession => ({
    sessionId: 'sess-1',
    clientId: 'client-1',
    redirectUri: 'https://app.example.com/callback',
    state: 'state-1',
    codeChallenge: 'challenge-1',
    codeChallengeMethod: 'S256',
    keyPairJwk: { kty: 'EC', crv: 'P-256', x: '...', y: '...', d: '...' },
    passphrase: 'pass-1',
    expiresAt: Math.floor(Date.now() / 1000) + 600,
    ...overrides
  })

  it('should save and retrieve a session', () => {
    const cache = new InMemoryAuthCache()
    const session = createSession()
    cache.save(session)
    const retrieved = cache.getAndDelete('sess-1')
    expect(retrieved).toEqual(session)
  })

  it('should delete session after retrieval', () => {
    const cache = new InMemoryAuthCache()
    const session = createSession()
    cache.save(session)
    cache.getAndDelete('sess-1')
    expect(cache.getAndDelete('sess-1')).toBeNull()
  })

  it('should not return expired sessions', () => {
    const cache = new InMemoryAuthCache()
    // Session expires in 10 seconds
    const session = createSession({ expiresAt: Math.floor(Date.now() / 1000) + 10 })
    cache.save(session)

    // Advance time by 11 seconds
    vi.advanceTimersByTime(11 * 1000)

    expect(cache.getAndDelete('sess-1')).toBeNull()
  })

  it('should cleanup expired entries on save', () => {
    const cache = new InMemoryAuthCache()
    // Session expires in 10 seconds
    const expired = createSession({ sessionId: 'expired', expiresAt: Math.floor(Date.now() / 1000) + 10 })
    const valid = createSession({ sessionId: 'valid', expiresAt: Math.floor(Date.now() / 1000) + 600 })

    cache.save(expired)

    // Advance time so the first session expires
    vi.advanceTimersByTime(15 * 1000)

    // This save should trigger cleanup
    cache.save(valid)

    // Verify 'expired' is gone from internal map
    const map = (cache as any).cache as Map<string, PreAuthSession>
    expect(map.has('expired')).toBe(false)
    expect(map.has('valid')).toBe(true)
  })

  it('should return null for non-existent session', () => {
    const cache = new InMemoryAuthCache()
    expect(cache.getAndDelete('non-existent')).toBeNull()
  })
})
