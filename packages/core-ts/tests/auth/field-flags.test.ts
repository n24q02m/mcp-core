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

  it('strict check for secret', () => {
    // biome-ignore lint/suspicious/noExplicitAny: testing runtime behavior
    expect(isSecretField({ name: 'F', label: 'L', required: true, secret: 1 as any })).toBe(false)
    expect(isSecretField({ name: 'F', label: 'L', required: true, secret: false })).toBe(false)
    expect(isSecretField({ name: 'F', label: 'L', required: true, secret: undefined })).toBe(false)
  })

  it('strict check for oauthField', () => {
    // biome-ignore lint/suspicious/noExplicitAny: testing runtime behavior
    expect(isOAuthField({ name: 'F', label: 'L', required: true, oauthField: 'true' as any })).toBe(false)
    expect(isOAuthField({ name: 'F', label: 'L', required: true, oauthField: false })).toBe(false)
    expect(isOAuthField({ name: 'F', label: 'L', required: true, oauthField: undefined })).toBe(false)
  })
})
