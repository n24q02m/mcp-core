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

// W4.4 light-mode: the shell + feature CSS declare a `prefers-color-scheme:
// light` override and `color-scheme: light dark` so the form is legible in a
// light OS theme instead of the previous dark-only hardcode.
describe('light-mode support', () => {
  it('the flat form declares light-mode CSS', () => {
    const html = renderCredentialForm(BASELINE_SCHEMA, { submitUrl: '/a' })
    expect(html).toContain('color-scheme: light dark')
    expect(html).toContain('@media (prefers-color-scheme: light)')
  })

  it('the tab form declares shell + tab light overrides', () => {
    const html = renderCredentialForm(
      {
        server: 's',
        displayName: 'S',
        tabs: [{ id: 'a', label: 'A', fields: [{ key: 'K', label: 'K', type: 'text' }] }]
      },
      { submitUrl: '/a' }
    )
    expect((html.match(/@media \(prefers-color-scheme: light\)/g) ?? []).length).toBeGreaterThanOrEqual(2)
  })

  it('the card form declares shell + card light overrides', () => {
    const html = renderCredentialForm(
      { server: 's', displayName: 'S', cardGroup: { key: 'items', fields: [{ key: 'K', label: 'K', type: 'text' }] } },
      { submitUrl: '/a' }
    )
    expect((html.match(/@media \(prefers-color-scheme: light\)/g) ?? []).length).toBeGreaterThanOrEqual(2)
  })
})

// WS3-7c: the shared form shell declares a Content-Security-Policy meta so the
// self-contained page runs its own inline script/style but loads nothing
// external. Applies to every form the shell renders (flat + tabs + cards).
const CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'"

describe('CSP meta', () => {
  it('the flat form embeds the CSP meta', () => {
    const html = renderCredentialForm(BASELINE_SCHEMA, { submitUrl: '/a' })
    expect(html).toContain(`<meta http-equiv="Content-Security-Policy" content="${CSP}" />`)
  })

  it('the tab form embeds the CSP meta', () => {
    const html = renderCredentialForm(
      {
        server: 's',
        displayName: 'S',
        tabs: [{ id: 'a', label: 'A', fields: [{ key: 'K', label: 'K', type: 'text' }] }]
      },
      { submitUrl: '/a' }
    )
    expect(html).toContain('http-equiv="Content-Security-Policy"')
    expect(html).toContain(CSP)
  })

  it('the card form embeds the CSP meta', () => {
    const html = renderCredentialForm(
      { server: 's', displayName: 'S', cardGroup: { key: 'items', fields: [{ key: 'K', label: 'K', type: 'text' }] } },
      { submitUrl: '/a' }
    )
    expect(html).toContain('http-equiv="Content-Security-Policy"')
    expect(html).toContain(CSP)
  })
})
