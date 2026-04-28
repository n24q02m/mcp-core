import { describe, expect, it } from 'vitest'

import { isSchemaComplete, type RelayConfigSchema } from '../../src/auth/credential-form.js'

const SCHEMA_REQUIRED_TOKEN: RelayConfigSchema = {
  server: 'demo',
  fields: [{ key: 'TOKEN', label: 'Token', type: 'password', required: true }]
}

const SCHEMA_WITH_GDRIVE: RelayConfigSchema = {
  server: 'wet-mcp-like',
  fields: [
    { key: 'JINA_AI_API_KEY', label: 'Jina', type: 'password', required: false },
    { key: 'GOOGLE_DRIVE_CLIENT_ID', label: 'GDrive', type: 'text', required: true }
  ]
}

const SCHEMA_ALL_OPTIONAL: RelayConfigSchema = {
  server: 'crg-like',
  fields: [
    { key: 'JINA_AI_API_KEY', label: 'Jina', type: 'password', required: false },
    { key: 'GEMINI_API_KEY', label: 'Gemini', type: 'password', required: false }
  ]
}

describe('runLocalServer auto-open gate', () => {
  it('opens when config is null', () => {
    expect(isSchemaComplete(null, SCHEMA_REQUIRED_TOKEN)).toBe(false)
  })

  it('skips when required field present', () => {
    expect(isSchemaComplete({ TOKEN: 'x' }, SCHEMA_REQUIRED_TOKEN)).toBe(true)
  })

  it('opens when peer-shared keys do not satisfy schema (regression for wet-mcp share-keys bug)', () => {
    expect(isSchemaComplete({ JINA_AI_API_KEY: 'shared_jina_from_crg' }, SCHEMA_WITH_GDRIVE)).toBe(false)
  })

  it('all-optional schema requires explicit _setup_complete=true', () => {
    expect(isSchemaComplete({}, SCHEMA_ALL_OPTIONAL)).toBe(false)
    expect(isSchemaComplete({ _setup_complete: 'true' }, SCHEMA_ALL_OPTIONAL)).toBe(true)
    expect(isSchemaComplete({ _setup_complete: 'false' }, SCHEMA_ALL_OPTIONAL)).toBe(false)
    expect(isSchemaComplete({ JINA_AI_API_KEY: 'k' }, SCHEMA_ALL_OPTIONAL)).toBe(false)
  })

  it('falls back to null-check when no schema (godot-like servers)', () => {
    // Mirrors run_local_server logic: schema undefined → fall back.
    const schema: RelayConfigSchema | undefined = undefined

    const decide = (config: Record<string, string> | null) =>
      schema ? isSchemaComplete(config, schema) : config !== null

    expect(decide(null)).toBe(false)
    expect(decide({ any_key: 'any_value' })).toBe(true)
  })
})
