import type { IncomingMessage } from 'node:http'
import { describe, expect, it } from 'vitest'

function parseCookies(req: IncomingMessage): Record<string, string> {
  const header = req.headers.cookie
  if (!header) return {}
  const out: Record<string, string> = {}

  // ⚡ Bolt: Single-pass while loop avoids array allocations from split(';') in hot path
  let pos = 0
  while (pos < header.length) {
    let end = header.indexOf(';', pos)
    if (end === -1) end = header.length

    const eq = header.indexOf('=', pos)
    if (eq !== -1 && eq < end) {
      const k = header.substring(pos, eq).trim()
      if (k.length > 0) {
        const v = header.substring(eq + 1, end).trim()
        out[k] = decodeURIComponent(v)
      }
    }

    pos = end + 1
  }
  return out
}

function mockReq(cookie?: string): IncomingMessage {
  return { headers: { cookie } } as IncomingMessage
}

describe('cookie parsing bench and edge cases', () => {
  it('handles empty or missing cookies', () => {
    expect(parseCookies(mockReq(undefined))).toEqual({})
    expect(parseCookies(mockReq(''))).toEqual({})
  })

  it('handles single cookie', () => {
    expect(parseCookies(mockReq('foo=bar'))).toEqual({ foo: 'bar' })
  })

  it('handles multiple cookies', () => {
    expect(parseCookies(mockReq('foo=bar; baz=qux'))).toEqual({ foo: 'bar', baz: 'qux' })
  })

  it('handles extra whitespace', () => {
    expect(parseCookies(mockReq('  foo = bar  ;   baz = qux  '))).toEqual({ foo: 'bar', baz: 'qux' })
  })

  it('handles empty value', () => {
    expect(parseCookies(mockReq('foo='))).toEqual({ foo: '' })
  })

  it('ignores empty key', () => {
    expect(parseCookies(mockReq('=bar'))).toEqual({})
  })

  it('handles multiple equals in value', () => {
    expect(parseCookies(mockReq('foo=bar=baz'))).toEqual({ foo: 'bar=baz' })
  })

  it('handles consecutive semicolons', () => {
    expect(parseCookies(mockReq('a=b;;;c=d'))).toEqual({ a: 'b', c: 'd' })
  })

  it('handles semicolons with spaces', () => {
    expect(parseCookies(mockReq('a=b; ; c=d'))).toEqual({ a: 'b', c: 'd' })
  })

  it('handles url encoded values', () => {
    expect(parseCookies(mockReq('foo=bar%20baz'))).toEqual({ foo: 'bar baz' })
  })
})
