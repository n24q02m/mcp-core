import { describe, expect, it } from 'vitest'

import { isSchemaComplete, type RelayConfigSchema } from '../../src/auth/credential-form.js'

const SCHEMA_2_REQUIRED_1_OPTIONAL: RelayConfigSchema = {
  server: 'demo',
  fields: [
    { key: 'API_KEY', label: 'API Key', type: 'password', required: true },
    { key: 'BASE_URL', label: 'Base URL', type: 'text', required: true },
    { key: 'TIMEOUT', label: 'Timeout', type: 'text', required: false }
  ]
}

const SCHEMA_ALL_OPTIONAL: RelayConfigSchema = {
  server: 'demo-optional',
  fields: [
    { key: 'OPT_A', label: 'Opt A', type: 'text', required: false },
    { key: 'OPT_B', label: 'Opt B', type: 'text', required: false }
  ]
}

describe('isSchemaComplete', () => {
  it('null config is incomplete', () => {
    expect(isSchemaComplete(null, SCHEMA_2_REQUIRED_1_OPTIONAL)).toBe(false)
  })

  it('undefined config is incomplete', () => {
    expect(isSchemaComplete(undefined, SCHEMA_2_REQUIRED_1_OPTIONAL)).toBe(false)
  })

  it('empty config is incomplete', () => {
    expect(isSchemaComplete({}, SCHEMA_2_REQUIRED_1_OPTIONAL)).toBe(false)
  })

  it('partial required is incomplete', () => {
    expect(isSchemaComplete({ API_KEY: 'k' }, SCHEMA_2_REQUIRED_1_OPTIONAL)).toBe(false)
  })

  it('all required present is complete', () => {
    expect(
      isSchemaComplete({ API_KEY: 'k', BASE_URL: 'https://x' }, SCHEMA_2_REQUIRED_1_OPTIONAL)
    ).toBe(true)
  })

  it('required present, optional missing is complete', () => {
    expect(
      isSchemaComplete({ API_KEY: 'k', BASE_URL: 'https://x' }, SCHEMA_2_REQUIRED_1_OPTIONAL)
    ).toBe(true)
  })

  it('required present with empty string is incomplete', () => {
    expect(
      isSchemaComplete({ API_KEY: 'k', BASE_URL: '' }, SCHEMA_2_REQUIRED_1_OPTIONAL)
    ).toBe(false)
  })

  it('all-optional schema with _setup_complete=true is complete', () => {
    expect(isSchemaComplete({ _setup_complete: 'true' }, SCHEMA_ALL_OPTIONAL)).toBe(true)
  })

  it('all-optional schema without flag is incomplete', () => {
    expect(isSchemaComplete({}, SCHEMA_ALL_OPTIONAL)).toBe(false)
  })

  it('all-optional schema with flag=false is incomplete', () => {
    expect(isSchemaComplete({ _setup_complete: 'false' }, SCHEMA_ALL_OPTIONAL)).toBe(false)
  })

  it('all-optional schema with arbitrary truthy string is incomplete (strict equality)', () => {
    expect(isSchemaComplete({ _setup_complete: 'yes' }, SCHEMA_ALL_OPTIONAL)).toBe(false)
  })
})
