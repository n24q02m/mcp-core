import { describe, expect, it } from 'vitest'
import { renderCredentialForm } from '../../src/auth/credential-form.js'

const CARD_SCHEMA = {
  server: 'better-email-mcp',
  displayName: 'Email MCP',
  description: 'Configure one or more email accounts.',
  cardGroup: {
    key: 'accounts',
    itemLabel: 'Account',
    heading: 'Email Accounts',
    addButtonLabel: '+ Add Another Account',
    minItems: 1,
    titleField: 'email',
    fields: [
      { key: 'email', label: 'Email Address', type: 'email', required: true, placeholder: 'you@example.com' },
      { key: 'password', label: 'Password', type: 'password', required: true },
      { key: 'imap_host', label: 'IMAP Host', type: 'text', required: false, helpText: 'Optional.' }
    ]
  }
}

const clone = () => JSON.parse(JSON.stringify(CARD_SCHEMA))
const render = (opts = {}) => renderCredentialForm(CARD_SCHEMA, { submitUrl: '/authorize?nonce=abc', ...opts })

describe('renderCredentialForm cardGroup', () => {
  it('renders the card-group scaffolding', () => {
    const html = render()
    expect(html).toContain('id="card-group-container"')
    expect(html).toContain('id="card-group-add"')
    expect(html).toContain('+ Add Another Account')
    expect(html).toContain('Email Accounts')
  })

  it('embeds the field spec for the JS builder', () => {
    const html = render()
    expect(html).toContain('var CARD_FIELDS = ')
    expect(html).toContain('GROUP_KEY = "accounts"')
    expect(html).toContain('TITLE_FIELD = "email"')
    expect(html).toContain('ITEM_LABEL = "Account"')
    expect(html).toContain('MIN_ITEMS = 1')
    for (const key of ['email', 'password', 'imap_host']) {
      expect(html).toContain(key)
    }
  })

  it('serialises cards as an array under the group key', () => {
    const html = render()
    expect(html).toContain('payload[GROUP_KEY] = items')
    expect(html).toContain('collectCards')
    expect(html).toContain('GROUP_KEY + "[" + cardUid + "]." + spec.key')
  })

  it('wires add + remove', () => {
    const html = render()
    expect(html).toContain('createCard')
    expect(html).toContain('addBtn.addEventListener("click"')
    expect(html).toContain('card.remove()')
    expect(html).toContain('MIN_ITEMS')
  })

  it('supports an Outlook-style device-code follow-up', () => {
    const html = render()
    expect(html).toContain('oauth_device_code')
    expect(html).toContain('setup-status')
    expect(html).toContain('renderOAuthDeviceCode')
  })

  it('guards the redirect target', () => {
    const html = render()
    expect(html).toContain('safeRedirect')
    expect(html).toContain('parsed.protocol === "http:"')
  })

  it('seeds multiple cards for minItems > 1', () => {
    const schema = clone()
    schema.cardGroup.minItems = 3
    const html = renderCredentialForm(schema, { submitUrl: '/a' })
    expect(html).toContain('MIN_ITEMS = 3')
  })

  it('escapes angle brackets in the embedded field JSON', () => {
    const schema = clone()
    schema.cardGroup.fields[0].placeholder = '</script><script>alert(1)</script>'
    const html = renderCredentialForm(schema, { submitUrl: '/a' })
    expect(html).not.toContain('</script><script>alert(1)')
    expect(html).toContain('\\u003c/script>')
  })

  it('escapes the group key in the JS literal', () => {
    const schema = clone()
    schema.cardGroup.key = 'x";alert(1);var y="'
    const html = renderCredentialForm(schema, { submitUrl: '/a' })
    expect(html).not.toContain('GROUP_KEY = "x";alert(1)')
  })

  it('uses safe DOM methods', () => {
    const html = render()
    expect(html).toContain('createElement')
    expect(html).toContain('textContent')
  })

  it('opts in the username field', () => {
    const html = render({ includeUsernameField: true })
    expect((html.match(/name="__sub_username"/g) ?? []).length).toBe(1)
  })
})
