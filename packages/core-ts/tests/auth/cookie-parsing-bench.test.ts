import { describe, expect, it } from 'vitest'

// Note: In `local-oauth-app.ts` and `delegated-oauth-app.ts`, `parseCookies` is a private
// helper nested inside the application closure (`createLocalOAuthApp` / `createDelegatedOAuthApp`).
// It's not exported or mockable without instantiating the entire OAuth server flow.
// This test provides isolated verification of the string-scanning logic,
// proving functional parity between `split(';')` and `indexOf()` for identical inputs.
// It acts as a safety harness for the optimization, independent of HTTP routes.

function parseCookiesOptimized(header?: string): Record<string, string> {
  if (!header) return {}
  const out: Record<string, string> = {}

  let pos = 0
  while (pos < header.length) {
    let nextSemi = header.indexOf(';', pos)
    if (nextSemi < 0) nextSemi = header.length

    const eq = header.indexOf('=', pos)
    if (eq >= 0 && eq < nextSemi) {
      const k = header.substring(pos, eq).trim()
      const v = header.substring(eq + 1, nextSemi).trim()
      if (k.length > 0) out[k] = decodeURIComponent(v)
    }

    pos = nextSemi + 1
  }
  return out
}

function parseCookiesOld(header?: string): Record<string, string> {
  if (!header) return {}
  const out: Record<string, string> = {}
  for (const part of header.split(';')) {
    const idx = part.indexOf('=')
    if (idx < 0) continue
    const k = part.slice(0, idx).trim()
    const v = part.slice(idx + 1).trim()
    if (k.length > 0) out[k] = decodeURIComponent(v)
  }
  return out
}

describe('Cookie Parsing Optimization Parity', () => {
  const cases = [
    { name: 'undefined header', cookie: undefined },
    { name: 'empty header', cookie: '' },
    { name: 'single simple cookie', cookie: 'session_id=12345' },
    { name: 'multiple simple cookies', cookie: 'session_id=12345; user_id=67890' },
    {
      name: 'multiple simple cookies with extra spaces',
      cookie: 'session_id=12345;    user_id=67890  ;  empty_val=  '
    },
    { name: 'cookie missing equals sign', cookie: 'session_id=12345; bad_cookie; user_id=67890' },
    { name: 'cookie with trailing semicolon', cookie: 'session_id=12345; user_id=67890;' },
    { name: 'empty key cookie', cookie: '=12345' },
    { name: 'multiple empty key cookies', cookie: '=12345; =67890' },
    { name: 'cookie with url encoded value', cookie: 'message=Hello%20World%21' },
    { name: 'cookie with multiple equals signs', cookie: 'session=abc=def=ghi' }
  ]

  for (const { name, cookie } of cases) {
    it(`should match old implementation for ${name}`, () => {
      const expected = parseCookiesOld(cookie)
      const actual = parseCookiesOptimized(cookie)
      expect(actual).toEqual(expected)
    })
  }
})
