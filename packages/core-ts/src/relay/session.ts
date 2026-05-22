import { randomBytes, timingSafeEqual } from 'node:crypto'

const SESSION_TTL_MS = 30 * 60 * 1000
const TOKEN_BYTES = 32

export interface ActiveFormSession {
  token: string
  clientId: string
  startedAt: Date
  expiresAt: Date
}

let state: ActiveFormSession | null = null

function now(): Date {
  return new Date()
}

export function claimSession(clientId: string): ActiveFormSession {
  if (state !== null && state.expiresAt > now()) {
    return state
  }
  const startedAt = now()
  state = {
    token: randomBytes(TOKEN_BYTES).toString('base64url'),
    clientId,
    startedAt,
    expiresAt: new Date(startedAt.getTime() + SESSION_TTL_MS)
  }
  return state
}

export function releaseSession(): void {
  state = null
}

export function isSessionActive(): boolean {
  if (state === null) return false
  if (state.expiresAt <= now()) {
    state = null
    return false
  }
  return true
}

export function validateSessionToken(token: string): boolean {
  if (state === null) return false
  if (state.expiresAt <= now()) {
    state = null
    return false
  }
  const a = Buffer.from(state.token)
  const b = Buffer.from(token)
  const isLengthEqual = a.length === b.length
  const compareB = isLengthEqual ? b : a
  return timingSafeEqual(a, compareB) && isLengthEqual
}

export function getActiveSession(): ActiveFormSession | null {
  if (state === null) return null
  if (state.expiresAt <= now()) {
    state = null
    return null
  }
  return state
}
