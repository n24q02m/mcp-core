import { describe, expect, it } from 'vitest'
import { authorizationServerMetadata, protectedResourceMetadata } from '../../src/auth/well-known.js'

describe('authorizationServerMetadata', () => {
  it('returns RFC 8414 metadata', () => {
    const meta = authorizationServerMetadata('http://127.0.0.1:9876')
    expect(meta.issuer).toBe('http://127.0.0.1:9876')
    expect(meta.authorization_endpoint).toBe('http://127.0.0.1:9876/authorize')
    expect(meta.token_endpoint).toBe('http://127.0.0.1:9876/token')
    expect(meta.response_types_supported).toEqual(['code'])
    expect(meta.grant_types_supported).toEqual(['authorization_code'])
    expect(meta.code_challenge_methods_supported).toEqual(['S256'])
    expect(meta.token_endpoint_auth_methods_supported).toEqual(['none'])
  })

  it('trims trailing slashes correctly', () => {
    // Issuer URL should be used as-is, no auto-stripping
    const meta = authorizationServerMetadata('http://example.com')
    expect(meta.authorization_endpoint).toBe('http://example.com/authorize')
  })
})

describe('protectedResourceMetadata', () => {
  it('returns RFC 9728 metadata', () => {
    const meta = protectedResourceMetadata('http://127.0.0.1:9876', ['http://127.0.0.1:9876'])
    expect(meta.resource).toBe('http://127.0.0.1:9876')
    expect(meta.authorization_servers).toEqual(['http://127.0.0.1:9876'])
    expect(meta.bearer_methods_supported).toEqual(['header'])
  })

  it('supports multiple authorization servers', () => {
    const meta = protectedResourceMetadata('http://api.example.com', [
      'http://auth1.example.com',
      'http://auth2.example.com'
    ])
    expect(meta.authorization_servers).toHaveLength(2)
  })
})
