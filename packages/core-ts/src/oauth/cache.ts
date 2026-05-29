export interface PreAuthSession {
  sessionId: string
  clientId: string
  redirectUri: string
  state: string
  codeChallenge: string
  codeChallengeMethod: string
  /** Serialized CryptoKeyPair for later credential retrieval */
  keyPairJwk: JsonWebKey
  passphrase: string
  expiresAt: number
}

export interface IOAuthSessionCache {
  save(session: PreAuthSession): void
  getAndDelete(sessionId: string): PreAuthSession | null
}

export class InMemoryAuthCache implements IOAuthSessionCache {
  private cache = new Map<string, PreAuthSession>()

  save(session: PreAuthSession): void {
    this.cache.set(session.sessionId, session)
    // Cleanup expired entries
    const now = Math.floor(Date.now() / 1000)
    for (const [id, sess] of this.cache) {
      if (sess.expiresAt < now) this.cache.delete(id)
    }
  }

  getAndDelete(sessionId: string): PreAuthSession | null {
    const sess = this.cache.get(sessionId)
    if (!sess) return null
    this.cache.delete(sessionId)
    if (sess.expiresAt < Math.floor(Date.now() / 1000)) return null
    return sess
  }
}
