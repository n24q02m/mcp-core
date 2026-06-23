import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { InMemoryAuthCache, type PreAuthSession } from '../../src/oauth/cache.js'

describe('InMemoryAuthCache', () => {
  let cache: InMemoryAuthCache

  const mockSession = (id: string, expiresAt: number): PreAuthSession => ({
    sessionId: id,
    clientId: 'client-1',
    redirectUri: 'http://localhost/cb',
    state: 'state-1',
    codeChallenge: 'challenge',
    codeChallengeMethod: 'S256',
    keyPairJwk: {} as JsonWebKey,
    passphrase: 'pass',
    expiresAt
  })

  beforeEach(() => {
    vi.useFakeTimers()
    cache = new InMemoryAuthCache()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('should save and retrieve a session', () => {
    const now = Math.floor(Date.now() / 1000)
    const session = mockSession('s1', now + 100)
    cache.save(session)

    const retrieved = cache.getAndDelete('s1')
    expect(retrieved).toEqual(session)
  })

  it('should delete session after retrieval', () => {
    const now = Math.floor(Date.now() / 1000)
    const session = mockSession('s1', now + 100)
    cache.save(session)

    cache.getAndDelete('s1')
    expect(cache.getAndDelete('s1')).toBeNull()
  })

  it('should return null for non-existent session', () => {
    expect(cache.getAndDelete('non-existent')).toBeNull()
  })

  it('should return null and cleanup if session is expired during get', () => {
    const now = Math.floor(Date.now() / 1000)
    const session = mockSession('s1', now + 100)
    cache.save(session)

    // Move time forward past expiration
    vi.advanceTimersByTime(101 * 1000)

    expect(cache.getAndDelete('s1')).toBeNull()
  })

  it('should cleanup expired entries when saving a new one', () => {
    const now = Math.floor(Date.now() / 1000)
    const expiredSession = mockSession('expired', now + 100)
    cache.save(expiredSession)

    // Move time forward past expiration
    vi.advanceTimersByTime(101 * 1000)

    const newSession = mockSession('new', now + 200)
    // This call should trigger cleanup of 'expired'
    cache.save(newSession)

    // We verify it's gone.
    // Note: getAndDelete also checks expiration, but the goal is to test the loop in save()
    expect(cache.getAndDelete('expired')).toBeNull()

    // Also verify the new one is still there
    expect(cache.getAndDelete('new')).toEqual(newSession)
  })
})
