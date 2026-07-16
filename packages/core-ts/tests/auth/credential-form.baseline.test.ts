import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { renderCredentialForm } from '../../src/auth/credential-form.js'

// Backward-compat guard: schemas that declare neither `tabs` nor `cardGroup`
// must render byte-for-byte identical to the pre-W4.1 renderer. The fixture is
// a golden capture; drift means an existing server (email/notion) could see its
// form change unexpectedly.
const FIXTURE = fileURLToPath(new URL('./fixtures/base_form_baseline.html', import.meta.url))

const BASELINE_SCHEMA = {
  server: 'golden-server',
  displayName: 'Golden Server',
  description: 'Backward-compat baseline form.',
  fields: [
    {
      key: 'API_TOKEN',
      label: 'API Token',
      type: 'password',
      placeholder: 'sk-...',
      required: true,
      helpText: 'Get your key',
      helpUrl: 'https://example.com/keys'
    },
    { key: 'WORKSPACE', label: 'Workspace', type: 'text', required: false }
  ],
  capabilityInfo: [{ label: 'Search', priority: 'high', description: 'Search the web' }]
}

describe('flat credential form backward-compat', () => {
  it('is byte-identical to the golden capture', () => {
    const html = renderCredentialForm(BASELINE_SCHEMA, {
      submitUrl: '/authorize?nonce=golden',
      prefill: { API_TOKEN: 'pre-filled' }
    })
    expect(html).toBe(readFileSync(FIXTURE, 'utf-8'))
  })

  it('emits no feature scaffolding for a plain schema', () => {
    const html = renderCredentialForm({ server: 's', displayName: 'S', fields: [] }, { submitUrl: '/a' })
    expect(html).not.toContain('role="tablist"')
    expect(html).not.toContain('card-group-container')
  })
})
