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
    expect(isSchemaComplete({ API_KEY: 'k', BASE_URL: 'https://x' }, SCHEMA_2_REQUIRED_1_OPTIONAL)).toBe(true)
  })

  it('required present, optional missing is complete', () => {
    expect(isSchemaComplete({ API_KEY: 'k', BASE_URL: 'https://x' }, SCHEMA_2_REQUIRED_1_OPTIONAL)).toBe(true)
  })

  it('required present with empty string is incomplete', () => {
    expect(isSchemaComplete({ API_KEY: 'k', BASE_URL: '' }, SCHEMA_2_REQUIRED_1_OPTIONAL)).toBe(false)
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

  it('schema with missing fields property defaults to empty list', () => {
    // `fields` is optional on RelayConfigSchema (schema-level tabs/cardGroup
    // schemas carry no top-level fields), so omitting it is well-typed.
    const schemaNoFields: RelayConfigSchema = { server: 'test' }
    expect(isSchemaComplete({ _setup_complete: 'true' }, schemaNoFields)).toBe(true)
    expect(isSchemaComplete({}, schemaNoFields)).toBe(false)
  })

  it('schema with null fields property defaults to empty list', () => {
    // @ts-expect-error testing runtime robustness for null fields
    const schemaNullFields: RelayConfigSchema = { server: 'test', fields: null }
    expect(isSchemaComplete({ _setup_complete: 'true' }, schemaNullFields)).toBe(true)
  })

  it('required=true as explicit boolean check (parity with core-py)', () => {
    const schema: RelayConfigSchema = {
      server: 'test',
      fields: [
        // @ts-expect-error testing non-boolean required
        { key: 'K', label: 'L', type: 'text', required: 'true' }
      ]
    }
    // "true" (string) is NOT true (boolean), so hasRequired remains false
    // falls through to _setup_complete check
    expect(isSchemaComplete({ K: 'v' }, schema)).toBe(false)
    expect(isSchemaComplete({ K: 'v', _setup_complete: 'true' }, schema)).toBe(true)
  })

  it('handles config values that are null or undefined for required fields', () => {
    const schema: RelayConfigSchema = {
      server: 'test',
      fields: [{ key: 'K', label: 'L', type: 'text', required: true }]
    }
    // Record<string, string> shouldn't have null/undefined values in theory,
    // but runtime objects from JSON.parse might.
    const configWithNull = { K: null } as unknown as Record<string, string>
    const configWithUndefined = { K: undefined } as unknown as Record<string, string>

    expect(isSchemaComplete(configWithNull, schema)).toBe(false)
    expect(isSchemaComplete(configWithUndefined, schema)).toBe(false)
  })

  it('ignores extra keys in config', () => {
    expect(isSchemaComplete({ API_KEY: 'k', BASE_URL: 'h', EXTRA: 'v' }, SCHEMA_2_REQUIRED_1_OPTIONAL)).toBe(true)
  })

  it('no fields in schema means it depends solely on _setup_complete', () => {
    const emptySchema: RelayConfigSchema = { server: 'test', fields: [] }
    expect(isSchemaComplete({ _setup_complete: 'true' }, emptySchema)).toBe(true)
    expect(isSchemaComplete({ _setup_complete: 'false' }, emptySchema)).toBe(false)
    expect(isSchemaComplete({}, emptySchema)).toBe(false)
  })

  it('_setup_complete check is strictly "true"', () => {
    const emptySchema: RelayConfigSchema = { server: 'test', fields: [] }
    // Case sensitivity
    expect(isSchemaComplete({ _setup_complete: 'TRUE' }, emptySchema)).toBe(false)
    // Non-string values if they sneak in
    const configWithBool = { _setup_complete: true } as unknown as Record<string, string>
    expect(isSchemaComplete(configWithBool, emptySchema)).toBe(false)
  })

  it('fields with required=undefined are treated as optional', () => {
    const schema: RelayConfigSchema = {
      server: 'test',
      fields: [{ key: 'OPT', label: 'Opt', type: 'text', required: undefined }]
    }
    // No required fields, so it falls through to _setup_complete
    expect(isSchemaComplete({}, schema)).toBe(false)
    expect(isSchemaComplete({ _setup_complete: 'true' }, schema)).toBe(true)
  })
})
