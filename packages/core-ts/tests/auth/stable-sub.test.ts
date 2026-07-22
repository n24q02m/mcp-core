/**
 * Unit + cross-language vector tests for ``deriveStableSub``.
 *
 * The vector cases are generated from core-py's ``derive_stable_sub`` and
 * asserted by BOTH languages against byte-identical copies of
 * ``tests/fixtures/crypto-vectors.json``, so the two implementations cannot
 * drift apart.
 */

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { deriveStableSub } from '../../src/auth/stable-sub.js'

interface StableSubVector {
  username: string
  server_name: string
  credential_secret: string | null
  expected: string
}

const vectorsPath = resolve(import.meta.dirname ?? '.', '..', 'fixtures', 'crypto-vectors.json')
const vectors: { stable_sub: StableSubVector[] } = JSON.parse(readFileSync(vectorsPath, 'utf-8'))

describe('deriveStableSub', () => {
  it('matches the core-py vectors byte for byte', () => {
    for (const v of vectors.stable_sub) {
      expect(deriveStableSub(v.username, v.server_name, v.credential_secret)).toBe(v.expected)
    }
  })

  it('is stable across whitespace and case', () => {
    const a = deriveStableSub('matthias', 'better-email-mcp', 's')
    const b = deriveStableSub('  MATTHIAS  ', 'better-email-mcp', 's')
    expect(a).toBe(b)
  })

  it('separates subjects by server name', () => {
    expect(deriveStableSub('u', 'a-mcp', 's')).not.toBe(deriveStableSub('u', 'b-mcp', 's'))
  })

  it('produces a token_urlsafe(16)-shaped value with no padding', () => {
    expect(deriveStableSub('u', 'a-mcp', 's')).toMatch(/^[A-Za-z0-9_-]{22}$/)
  })

  it('rejects a blank username', () => {
    expect(() => deriveStableSub('   ', 'a-mcp', 's')).toThrow('username must be non-empty')
  })

  // Documents a KNOWN divergence from core-py: Python casefold() maps
  // sharp-s to 'ss', JavaScript toLowerCase() does not. Locked so the gap
  // cannot widen unnoticed; parity vectors cover ASCII only.
  it('documents the non-ASCII casefold divergence', () => {
    expect(deriveStableSub('straße', 'a-mcp', 's')).not.toBe(deriveStableSub('strasse', 'a-mcp', 's'))
  })
})
