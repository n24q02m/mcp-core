import { describe, expect, it } from 'vitest'
import { verifyPKCE } from '../../src/oauth/pkce.js'

describe('verifyPKCE', () => {
  // RFC 7636 Appendix B test vectors
  const codeVerifier = 'dBjM5989tV_pj366is_aeZon7O39TV-as3xxuMWHqNE'
  const codeChallengeS256 = '6xmo-AXVO5jmd9dC3MDa6Ql3XTUeCIhjTz3RlbNbnSg'

  describe('S256 method', () => {
    it('should succeed with valid code verifier and challenge', () => {
      expect(() => verifyPKCE(codeVerifier, codeChallengeS256, 'S256')).not.toThrow()
    })

    it('should throw with invalid code verifier', () => {
      expect(() => verifyPKCE('wrong_verifier', codeChallengeS256, 'S256')).toThrow(
        'invalid_grant: PKCE verification failed'
      )
    })

    it('should throw with invalid code challenge', () => {
      expect(() => verifyPKCE(codeVerifier, 'wrong_challenge', 'S256')).toThrow(
        'invalid_grant: PKCE verification failed'
      )
    })

    it('should throw when lengths differ significantly (timing attack mitigation check)', () => {
      // verifyPKCE uses timingSafeEqual, it should handle length differences safely
      expect(() => verifyPKCE(codeVerifier, 'short', 'S256')).toThrow('invalid_grant: PKCE verification failed')
    })
  })

  describe('plain method', () => {
    it('should succeed when verifier matches challenge', () => {
      expect(() => verifyPKCE('my_verifier', 'my_verifier', 'plain')).not.toThrow()
    })

    it('should throw when verifier does not match challenge', () => {
      expect(() => verifyPKCE('my_verifier', 'other_verifier', 'plain')).toThrow(
        'invalid_grant: PKCE plain verification failed'
      )
    })
  })

  describe('unsupported methods', () => {
    it('should throw for unknown method', () => {
      expect(() => verifyPKCE(codeVerifier, codeChallengeS256, 'unknown')).toThrow('unsupported_challenge_method')
    })
  })
})
