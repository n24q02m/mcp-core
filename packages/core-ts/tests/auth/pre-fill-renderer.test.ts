import { describe, expect, it } from 'vitest'
import type { RelayConfigField } from '../../src/auth/credential-form.js'
import { mergeSubmission, renderField } from '../../src/auth/local-oauth-app.js'

const SCHEMA_FIELDS: RelayConfigField[] = [
  { name: 'BASE_URL', label: 'Base URL', required: true },
  { name: 'API_KEY', label: 'API Key', required: true, secret: true },
  { name: 'REFRESH_TOKEN', label: 'Refresh', required: false, oauthField: true }
]

describe('pre-fill renderer', () => {
  it('non-secret with value', () => {
    const html = renderField(SCHEMA_FIELDS[0], 'https://api.example.com')
    expect(html).toContain('value="https://api.example.com"')
    expect(html).toContain('name="BASE_URL"')
  })

  it('non-secret empty', () => {
    const html = renderField(SCHEMA_FIELDS[0], null)
    expect(html).toMatch(/value=""|name="BASE_URL"\s*>/)
  })

  it('secret with value', () => {
    const html = renderField(SCHEMA_FIELDS[1], 'sk_live_xxx')
    expect(html).not.toContain('sk_live_xxx')
    expect(html.toLowerCase()).toContain('configured')
    expect(html).toContain('value=""')
  })

  it('secret empty', () => {
    const html = renderField(SCHEMA_FIELDS[1], null)
    expect(html).toContain('API Key')
    expect(html).toMatch(/value=""|name="API_KEY"\s*>/)
  })

  it('oauth field button', () => {
    const html = renderField(SCHEMA_FIELDS[2], 'rt_xxx')
    expect(html).not.toContain('rt_xxx')
    expect(html).toMatch(/Re-authorize|reauthorize/i)
  })

  it('merge preserves secret on empty', () => {
    const result = mergeSubmission(
      { BASE_URL: 'old', API_KEY: 'secret-old' },
      { BASE_URL: 'new', API_KEY: '' },
      SCHEMA_FIELDS
    )
    expect(result.BASE_URL).toBe('new')
    expect(result.API_KEY).toBe('secret-old')
  })

  it('merge replaces secret on new', () => {
    const result = mergeSubmission({ API_KEY: 'old' }, { API_KEY: 'new' }, [SCHEMA_FIELDS[1]])
    expect(result.API_KEY).toBe('new')
  })

  it('merge replaces non-secret on empty', () => {
    const result = mergeSubmission({ BASE_URL: 'old' }, { BASE_URL: '' }, [SCHEMA_FIELDS[0]])
    expect(result.BASE_URL).toBe('')
  })
})
