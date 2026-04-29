import { describe, expect, it } from 'vitest'
import { isOAuthField, isSecretField, type RelayConfigField } from '../../src/auth/credential-form.js'

describe('field flags', () => {
  it('default not secret', () => {
    const f: RelayConfigField = { name: 'BASE_URL', label: 'Base URL', required: true }
    expect(isSecretField(f)).toBe(false)
    expect(isOAuthField(f)).toBe(false)
  })

  it('explicit secret', () => {
    const f: RelayConfigField = { name: 'API_KEY', label: 'API Key', required: true, secret: true }
    expect(isSecretField(f)).toBe(true)
  })

  it('oauth field', () => {
    const f: RelayConfigField = { name: 'refresh_token', label: 'Refresh Token', required: true, oauthField: true }
    expect(isOAuthField(f)).toBe(true)
  })

  it('oauth and secret disjoint', () => {
    const f: RelayConfigField = {
      name: 'refresh_token',
      label: 'Refresh Token',
      required: true,
      oauthField: true,
      secret: true
    }
    expect(isOAuthField(f)).toBe(true)
    expect(isSecretField(f)).toBe(true)
  })
})
