import { describe, expect, it } from 'vitest'
import { renderCredentialForm } from '../../src/auth/credential-form.js'

describe('renderCredentialForm', () => {
  it('renders basic form with fields', () => {
    const html = renderCredentialForm(
      {
        server: 'test-server',
        displayName: 'Test Server',
        description: 'Enter your API key.',
        fields: [
          {
            key: 'API_KEY',
            label: 'API Key',
            type: 'password',
            placeholder: 'sk-...',
            required: true
          }
        ]
      },
      { submitUrl: '/authorize?nonce=abc' }
    )
    expect(html).toContain('<!DOCTYPE html>')
    expect(html).toContain('Test Server')
    expect(html).toContain('API_KEY')
    expect(html).toContain('sk-...')
    expect(html).toContain('/authorize?nonce=abc')
  })

  it('escapes XSS in displayName', () => {
    const html = renderCredentialForm(
      { server: 'test', displayName: '<script>alert("xss")</script>', fields: [] },
      { submitUrl: '/submit' }
    )
    expect(html).not.toContain('<script>alert')
    expect(html).toContain('&lt;script&gt;')
  })

  it('escapes XSS in field values', () => {
    const html = renderCredentialForm(
      {
        server: 'test',
        displayName: 'Test',
        fields: [
          {
            key: '<img>',
            label: '<svg>',
            type: '<iframe>',
            placeholder: '<a>',
            required: true
          }
        ]
      },
      { submitUrl: '/submit' }
    )
    expect(html).not.toContain('<img>')
    expect(html).not.toContain('<svg>')
  })

  it('includes multi-step auth JS handlers', () => {
    const html = renderCredentialForm(
      { server: 'test', displayName: 'Test', fields: [] },
      { submitUrl: '/authorize?nonce=abc' }
    )
    expect(html).toContain('otp_required')
    expect(html).toContain('password_required')
    expect(html).toContain('/otp')
  })

  it('includes oauth device code handler', () => {
    const html = renderCredentialForm(
      { server: 'test', displayName: 'Test', fields: [] },
      { submitUrl: '/authorize?nonce=abc' }
    )
    expect(html).toContain('oauth_device_code')
    expect(html).toContain('setup-status')
  })

  it('uses safe DOM methods in JS (createElement + textContent)', () => {
    const html = renderCredentialForm(
      { server: 'test', displayName: 'Test', fields: [] },
      { submitUrl: '/authorize?nonce=abc' }
    )
    expect(html).toContain('createElement')
    expect(html).toContain('textContent')
  })

  it('includes step input accessibility (aria-labelledby)', () => {
    const html = renderCredentialForm(
      { server: 'test', displayName: 'Test', fields: [] },
      { submitUrl: '/authorize?nonce=abc' }
    )
    expect(html).toMatch(/setAttribute\s*\(\s*["']aria-labelledby["']/)
  })

  it('renders optional fields with correct marker', () => {
    const html = renderCredentialForm(
      {
        server: 'test',
        displayName: 'Test',
        fields: [{ key: 'OPT', label: 'Opt', type: 'text', required: false }]
      },
      { submitUrl: '/submit' }
    )
    expect(html).toContain('Optional')
  })

  it('renders capability info section', () => {
    const html = renderCredentialForm(
      {
        server: 'test',
        displayName: 'Test',
        fields: [],
        capabilityInfo: [{ label: 'Feature', priority: 'high', description: 'important' }]
      },
      { submitUrl: '/submit' }
    )
    expect(html).toContain('Feature')
    expect(html).toContain('important')
  })

  it('fetch posts step to /otp URL derived from submit URL', () => {
    const html = renderCredentialForm(
      { server: 'test', displayName: 'Test', fields: [] },
      { submitUrl: '/authorize?nonce=abc' }
    )
    expect(html).toMatch(/fetch\(\s*otpUrl\(\)\s*,\s*\{[^}]*method:\s*["']POST["']/)
  })

  it('defaults page title to displayName when not provided', () => {
    const html = renderCredentialForm({ server: 'test', displayName: 'My App', fields: [] }, { submitUrl: '/submit' })
    expect(html).toMatch(/<title>My App<\/title>/)
  })

  it('uses custom page title when provided', () => {
    const html = renderCredentialForm(
      { server: 'test', displayName: 'My App', fields: [] },
      { submitUrl: '/submit', pageTitle: 'Custom Title' }
    )
    expect(html).toMatch(/<title>Custom Title<\/title>/)
  })

  it('falls back to server when displayName is missing', () => {
    const html = renderCredentialForm({ server: 'my-server', fields: [] }, { submitUrl: '/submit' })
    expect(html).toContain('my-server')
  })

  it('renders help text with URL as a link', () => {
    const html = renderCredentialForm(
      {
        server: 'test',
        displayName: 'Test',
        fields: [
          {
            key: 'X',
            label: 'X',
            type: 'text',
            helpText: 'Get your key',
            helpUrl: 'https://example.com/docs'
          }
        ]
      },
      { submitUrl: '/submit' }
    )
    expect(html).toContain('href="https://example.com/docs"')
    expect(html).toContain('Get your key')
    expect(html).toContain('target="_blank"')
    expect(html).toContain('rel="noopener noreferrer"')
  })

  it('renders help text without URL as plain paragraph', () => {
    const html = renderCredentialForm(
      {
        server: 'test',
        displayName: 'Test',
        fields: [{ key: 'X', label: 'X', type: 'text', helpText: 'Just help' }]
      },
      { submitUrl: '/submit' }
    )
    expect(html).toContain('<p class="help-text" id="help-X">Just help</p>')
  })

  it('applies priority-medium class when capability priority is empty', () => {
    const html = renderCredentialForm(
      {
        server: 'test',
        displayName: 'Test',
        fields: [],
        capabilityInfo: [{ label: 'Feat' }]
      },
      { submitUrl: '/submit' }
    )
    expect(html).toContain('priority-medium')
  })

  it('applies matching priority class when capability priority is set', () => {
    const html = renderCredentialForm(
      {
        server: 'test',
        displayName: 'Test',
        fields: [],
        capabilityInfo: [{ label: 'Feat', priority: 'low' }]
      },
      { submitUrl: '/submit' }
    )
    expect(html).toContain('priority-low')
  })

  it('omits capabilities section when capabilityInfo is absent', () => {
    const html = renderCredentialForm({ server: 'test', displayName: 'Test', fields: [] }, { submitUrl: '/submit' })
    expect(html).not.toContain('Capabilities Requested')
  })

  it('escapes submit URL used in the JS string literal', () => {
    const html = renderCredentialForm(
      { server: 'test', displayName: 'Test', fields: [] },
      { submitUrl: '/authorize?"onerror="alert(1)' }
    )
    // The double-quote in the URL must be HTML-escaped so it cannot break out
    // of the surrounding "..." JS string literal embedded inside <script>.
    expect(html).not.toContain('"onerror="alert(1)')
    expect(html).toContain('&quot;onerror=&quot;alert(1)')
  })

  it('escapes XSS in description', () => {
    const html = renderCredentialForm(
      {
        server: 'test',
        displayName: 'Test',
        description: '<script>bad()</script>',
        fields: []
      },
      { submitUrl: '/submit' }
    )
    expect(html).not.toContain('<script>bad()')
    expect(html).toContain('&lt;script&gt;bad()')
  })

  it('renders /authorize -> /otp regex in JS verbatim', () => {
    const html = renderCredentialForm(
      { server: 'test', displayName: 'Test', fields: [] },
      { submitUrl: '/authorize?nonce=abc' }
    )
    // Python outputs: submitUrl.replace(/\/authorize.*/, "/otp")
    expect(html).toContain(String.raw`submitUrl.replace(/\/authorize.*/, "/otp")`)
  })

  it('renders /authorize -> /setup-status regex for oauth poll verbatim', () => {
    const html = renderCredentialForm(
      { server: 'test', displayName: 'Test', fields: [] },
      { submitUrl: '/authorize?nonce=abc' }
    )
    expect(html).toContain(String.raw`submitUrl.replace(/\/authorize.*/, "/setup-status")`)
  })

  it('poll handler detects error:<msg> status and surfaces the message', () => {
    // Without this branch a Google device code failure leaves the browser
    // waiting forever. Detection check + message surfacing + retry hint.
    const html = renderCredentialForm(
      { server: 'test', displayName: 'Test', fields: [] },
      { submitUrl: '/authorize?nonce=abc' }
    )
    expect(html).toContain('indexOf("error:") === 0')
    expect(html).toContain('Google Drive authorization failed')
    expect(html).toContain('Please retry setup')
  })
})
