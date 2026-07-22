/**
 * Derive a stable, opaque subject id from a workspace username.
 *
 * TypeScript port of core-py's ``stable_sub.py``. Output is byte-identical for
 * ASCII usernames, locked by the shared ``crypto-vectors.json`` fixture.
 */

import { createHmac } from 'node:crypto'

// Used only when CREDENTIAL_SECRET is unset (single-user/dev): the sub stays
// stable, just predictable. Production multi-user always sets CREDENTIAL_SECRET.
const DEV_FALLBACK_KEY = Buffer.from('mcp-core-stable-sub-dev-salt', 'utf-8')

/**
 * Derive a stable, opaque subject id from a workspace username.
 *
 * Same ``(serverName, normalized username)`` -> same ``sub``, so a returning
 * user lands on the same per-``sub`` credential bucket instead of the random
 * subject minted per ``/authorize``. The output shape (22 chars, urlsafe
 * base64, no padding) matches ``randomBytes(16).toString('base64url')`` so
 * downstream code cannot tell a stable sub from a random one.
 *
 * Normalization is ``trim().toLowerCase()``. Python's ``str.casefold()`` maps
 * a few non-ASCII characters differently (``'ß'.casefold() == 'ss'``), so
 * cross-language parity is guaranteed for ASCII usernames only; the divergence
 * is asserted by a test in both languages.
 *
 * SECURITY: with a SHARED relay password the username is a PARTITION key, NOT a
 * secret -- anyone who knows the password can submit any username and reach that
 * bucket. Intentional for a trusted group; untrusted multi-tenant needs per-user
 * secrets or delegated OAuth.
 */
export function deriveStableSub(
  username: string,
  serverName: string,
  credentialSecret: string | null | undefined
): string {
  const normalized = username.trim().toLowerCase()
  if (!normalized) throw new Error('username must be non-empty')
  const key = credentialSecret ? Buffer.from(credentialSecret, 'utf-8') : DEV_FALLBACK_KEY
  const digest = createHmac('sha256', key).update(`sub:${serverName}:${normalized}`, 'utf8').digest()
  return digest.subarray(0, 16).toString('base64url')
}
