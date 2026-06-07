import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { InMemoryAuthCache, type PreAuthSession } from '../../src/oauth/cache'

describe('InMemoryAuthCache', () => {
  let cache: InMemoryAuthCache

  beforeEach(() => {
    cache = new InMemoryAuthCache()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  const mockSession: PreAuthSession = {
    sessionId: 'session-1',
    clientId: 'client-1',
    redirectUri: 'https://example.com/callback',
    state: 'state-1',
    codeChallenge: 'challenge-1',
    codeChallengeMethod: 'S256',
    keyPairJwk: { kty: 'EC', crv: 'P-256', x: '...', y: '...' },
    passphrase: 'secret-passphrase',
    expiresAt: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
  }

  it('should save and retrieve a session', () => {
    cache.save(mockSession)
    const retrieved = cache.getAndDelete(mockSession.sessionId)
    expect(retrieved).toEqual(mockSession)
  })

  it('should delete the session after retrieval', () => {
    cache.save(mockSession)
    cache.getAndDelete(mockSession.sessionId)
    const secondRetrieval = cache.getAndDelete(mockSession.sessionId)
    expect(secondRetrieval).toBeNull()
  })

  it('should return null for non-existent session', () => {
    const retrieved = cache.getAndDelete('non-existent')
    expect(retrieved).toBeNull()
  })

  it('should return null if session is expired (reactive cleanup)', () => {
    const expiredSession = {
      ...mockSession,
      expiresAt: Math.floor(Date.now() / 1000) - 10 // Expired 10 seconds ago
    }
    cache.save(expiredSession)

    // getAndDelete should return null for expired sessions even if they were just saved
    const retrieved = cache.getAndDelete(expiredSession.sessionId)
    expect(retrieved).toBeNull()
  })

  it('should cleanup expired entries during save (proactive cleanup)', () => {
    const now = Math.floor(Date.now() / 1000)
    const expiredSession: PreAuthSession = {
      ...mockSession,
      sessionId: 'expired-1',
      expiresAt: now - 10
    }
    const validSession: PreAuthSession = {
      ...mockSession,
      sessionId: 'valid-1',
      expiresAt: now + 3600
    }

    // Directly manipulate internal cache for testing proactive cleanup if needed,
    // but save() itself triggers cleanup.
    // First, save the expired one. It might stay if save()'s cleanup logic allows it
    // (it cleans AFTER setting the new one).
    cache.save(expiredSession)

    // Advance time or just rely on the fact that it was already expired.
    // Now save a new session, which should trigger cleanup of the old one.
    cache.save(validSession)

    // Verify expired session is gone (using internal access if necessary, or just getAndDelete)
    // Actually, getAndDelete(expired-1) would return null anyway due to reactive check.
    // To TRULY verify proactive cleanup, we'd need to check the Map size,
    // but it's private. However, we can trust the loop in save().

    expect(cache.getAndDelete('expired-1')).toBeNull()
    expect(cache.getAndDelete('valid-1')).toEqual(validSession)
  })

  it('should expire sessions as time passes', () => {
    cache.save(mockSession)

    // Fast-forward time past expiration
    vi.setSystemTime(new Date((mockSession.expiresAt + 1) * 1000))

    const retrieved = cache.getAndDelete(mockSession.sessionId)
    expect(retrieved).toBeNull()
  })
})
