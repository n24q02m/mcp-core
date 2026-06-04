import { describe, expect, it } from 'vitest'
import { verifyPKCE } from '../../src/oauth/pkce.js'

describe('verifyPKCE', () => {
  // Test vectors verified against node:crypto
  const codeVerifier = 'dBjM5989tV_pj366is_aeZon7O39TV-as3xxuMWHqNE'
  const codeChallenge = '6xmo-AXVO5jmd9dC3MDa6Ql3XTUeCIhjTz3RlbNbnSg'

  describe('S256 method', () => {
    it('successfully verifies a valid S256 challenge', () => {
      expect(() => verifyPKCE(codeVerifier, codeChallenge, 'S256')).not.toThrow()
    })

    it('throws invalid_grant when the challenge does not match', () => {
      expect(() => verifyPKCE(codeVerifier, 'wrong_challenge', 'S256')).toThrow(
        'invalid_grant: PKCE verification failed'
      )
    })

    it('throws invalid_grant when the challenge length is different', () => {
      expect(() => verifyPKCE(codeVerifier, codeChallenge.slice(0, -1), 'S256')).toThrow(
        'invalid_grant: PKCE verification failed'
      )
    })

    it('throws invalid_grant when the verifier is wrong', () => {
      expect(() => verifyPKCE('wrong_verifier', codeChallenge, 'S256')).toThrow(
        'invalid_grant: PKCE verification failed'
      )
    })
  })

  describe('plain method', () => {
    it('successfully verifies a valid plain challenge', () => {
      expect(() => verifyPKCE('plain_verifier', 'plain_verifier', 'plain')).not.toThrow()
    })

    it('throws invalid_grant when the plain challenge does not match', () => {
      expect(() => verifyPKCE('plain_verifier', 'wrong_challenge', 'plain')).toThrow(
        'invalid_grant: PKCE plain verification failed'
      )
    })

    it('throws invalid_grant when the plain challenge length is different', () => {
      expect(() => verifyPKCE('plain_verifier', 'plain_verifie', 'plain')).toThrow(
        'invalid_grant: PKCE plain verification failed'
      )
    })
  })

  describe('unsupported method', () => {
    it('throws unsupported_challenge_method for unknown methods', () => {
      expect(() => verifyPKCE(codeVerifier, codeChallenge, 'S512')).toThrow('unsupported_challenge_method')

      expect(() => verifyPKCE(codeVerifier, codeChallenge, '')).toThrow('unsupported_challenge_method')
    })
  })
})
