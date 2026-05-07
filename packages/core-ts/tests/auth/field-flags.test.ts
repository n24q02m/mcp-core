import { describe, expect, it } from 'vitest'
import { isOAuthField, isSecretField, type RelayConfigField } from '../../src/auth/credential-form.js'

describe('field flags', () => {
  it('isSecretField: handles true, false, and undefined', () => {
    expect(isSecretField({ name: 'f', label: 'L', required: true, secret: true })).toBe(true)
    expect(isSecretField({ name: 'f', label: 'L', required: true, secret: false })).toBe(false)
    expect(isSecretField({ name: 'f', label: 'L', required: true })).toBe(false)
  })

  it('isOAuthField: handles true, false, and undefined', () => {
    expect(isOAuthField({ name: 'f', label: 'L', required: true, oauthField: true })).toBe(true)
    expect(isOAuthField({ name: 'f', label: 'L', required: true, oauthField: false })).toBe(false)
    expect(isOAuthField({ name: 'f', label: 'L', required: true })).toBe(false)
  })

  it('strict boolean checks (prevents truthy leakage)', () => {
    // These tests verify that only literal `true` returns true, as required by the implementation.

    // @ts-expect-error - testing runtime behavior for non-boolean truthy values
    expect(isSecretField({ name: 'f', label: 'L', required: true, secret: 1 })).toBe(false)

    // @ts-expect-error
    expect(isSecretField({ name: 'f', label: 'L', required: true, secret: 'true' })).toBe(false)

    // @ts-expect-error
    expect(isOAuthField({ name: 'f', label: 'L', required: true, oauthField: 1 })).toBe(false)

    // @ts-expect-error
    expect(isOAuthField({ name: 'f', label: 'L', required: true, oauthField: 'true' })).toBe(false)
  })

  it('oauth and secret can be used together', () => {
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
