import { createHash, timingSafeEqual } from 'node:crypto'

/**
 * Verify PKCE code challenge.
 * Throws an error if verification fails.
 *
 * @param codeVerifier The PKCE code verifier.
 * @param codeChallenge The stored code challenge.
 * @param method The code challenge method (S256 or plain).
 */
export function verifyPKCE(codeVerifier: string, codeChallenge: string, method: string): void {
  if (method === 'S256') {
    const digest = createHash('sha256').update(codeVerifier).digest('base64url')
    const expected = Buffer.from(digest)
    const actual = Buffer.from(codeChallenge)
    const isLengthEqual = expected.length === actual.length
    const compareActual = isLengthEqual ? actual : expected
    if (!timingSafeEqual(expected, compareActual) || !isLengthEqual) {
      throw new Error('invalid_grant: PKCE verification failed')
    }
  } else if (method === 'plain') {
    const expected = Buffer.from(codeVerifier)
    const actual = Buffer.from(codeChallenge)
    const isLengthEqual = expected.length === actual.length
    const compareActual = isLengthEqual ? actual : expected
    if (!timingSafeEqual(expected, compareActual) || !isLengthEqual) {
      throw new Error('invalid_grant: PKCE plain verification failed')
    }
  } else {
    throw new Error('unsupported_challenge_method')
  }
}
