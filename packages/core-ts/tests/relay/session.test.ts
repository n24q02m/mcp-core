import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  claimSession,
  getActiveSession,
  isSessionActive,
  releaseSession,
  validateSessionToken
} from '../../src/relay/session.js'

describe('active form session', () => {
  beforeEach(() => releaseSession())
  afterEach(() => releaseSession())

  it('claim returns token', () => {
    const s = claimSession('bridge-1')
    expect(s.token).toBeTruthy()
    expect(s.clientId).toBe('bridge-1')
    expect(s.expiresAt.getTime()).toBeGreaterThan(s.startedAt.getTime())
  })

  it('second claim returns existing', () => {
    const a = claimSession('bridge-1')
    const b = claimSession('bridge-2')
    expect(b.token).toBe(a.token)
    expect(b.clientId).toBe('bridge-1')
  })

  it('is_session_active after claim', () => {
    claimSession('bridge-1')
    expect(isSessionActive()).toBe(true)
  })

  it('release clears session', () => {
    claimSession('bridge-1')
    releaseSession()
    expect(isSessionActive()).toBe(false)
  })

  it('session expires after ttl', () => {
    const s = claimSession('bridge-1')
    vi.setSystemTime(new Date(s.expiresAt.getTime() + 1000))
    expect(isSessionActive()).toBe(false)
    vi.useRealTimers()
  })

  it('validate token match', () => {
    const s = claimSession('bridge-1')
    expect(validateSessionToken(s.token)).toBe(true)
  })

  it('validate token mismatch', () => {
    claimSession('bridge-1')
    expect(validateSessionToken('wrong')).toBe(false)
  })

  it('validate token no session', () => {
    expect(validateSessionToken('any')).toBe(false)
  })
})
