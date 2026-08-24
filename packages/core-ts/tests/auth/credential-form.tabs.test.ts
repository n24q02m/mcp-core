import { describe, expect, it } from 'vitest'
import { renderCredentialForm } from '../../src/auth/credential-form.js'

const TABS_SCHEMA = {
  server: 'better-telegram-mcp',
  displayName: 'Telegram MCP',
  description: 'Bot token or phone login.',
  tabs: [
    {
      id: 'bot',
      label: 'Bot Mode',
      fields: [
        {
          key: 'TELEGRAM_BOT_TOKEN',
          label: 'Bot Token',
          type: 'password',
          required: true,
          placeholder: '123456:ABC-DEF...',
          helpText: 'Get from @BotFather',
          helpUrl: 'https://core.telegram.org/bots#botfather'
        }
      ]
    },
    {
      id: 'user',
      label: 'User Mode',
      fields: [{ key: 'TELEGRAM_PHONE', label: 'Phone Number', type: 'tel', required: true, placeholder: '+84...' }]
    }
  ]
}

const render = (opts = {}) => renderCredentialForm(TABS_SCHEMA, { submitUrl: '/authorize?nonce=abc', ...opts })

describe('renderCredentialForm tabs', () => {
  it('renders one button + panel per tab', () => {
    const html = render()
    expect(html).toContain('role="tablist"')
    expect((html.match(/role="tab"/g) ?? []).length).toBe(2)
    expect((html.match(/role="tabpanel"/g) ?? []).length).toBe(2)
    expect(html).toContain('id="tab-bot"')
    expect(html).toContain('id="tab-user"')
    expect(html).toContain('id="panel-bot"')
    expect(html).toContain('id="panel-user"')
    expect(html).toContain('Bot Mode')
    expect(html).toContain('User Mode')
  })

  it('references the server description when present', () => {
    const html = render()
    expect(html).toContain('id="server-desc"')
    expect(html).toContain('<form id="credential-form" aria-describedby="server-desc" novalidate>')
  })

  it('omits the description reference when absent', () => {
    const html = renderCredentialForm({ ...TABS_SCHEMA, description: '' }, { submitUrl: '/authorize' })
    expect(html).not.toContain('id="server-desc"')
    expect(html).not.toContain('aria-describedby="server-desc"')
  })

  it('activates the first tab by default', () => {
    const html = render()
    expect(html).toContain('id="tab-bot" class="tab active"')
    expect(html).toContain('id="panel-bot" class="tab-panel active"')
    expect(html).toContain('id="tab-user" class="tab"')
  })

  it('honours the initialTab option', () => {
    const html = render({ initialTab: 'user' })
    expect(html).toContain('id="tab-user" class="tab active"')
    expect(html).toContain('id="panel-user" class="tab-panel active"')
    expect(html).toContain('id="tab-bot" class="tab"')
  })

  it('falls back to the first tab for an unknown initialTab', () => {
    const html = render({ initialTab: 'nope' })
    expect(html).toContain('id="tab-bot" class="tab active"')
  })

  it('scopes each panel to its own fields', () => {
    const html = render()
    const botPanel = html.split('id="panel-bot"')[1].split('id="panel-user"')[0]
    const userPanel = html.split('id="panel-user"')[1].split('</form>')[0]
    expect(botPanel).toContain('name="TELEGRAM_BOT_TOKEN"')
    expect(botPanel).not.toContain('name="TELEGRAM_PHONE"')
    expect(userPanel).toContain('name="TELEGRAM_PHONE"')
    expect(userPanel).not.toContain('name="TELEGRAM_BOT_TOKEN"')
  })

  it('submits only the active panel fields', () => {
    const html = render()
    expect(html).toContain('document.querySelector(".tab-panel.active")')
    expect(html).toContain('activePanel ? activePanel.querySelectorAll(".field-input")')
  })

  it('wires arrow-key tablist navigation', () => {
    const html = render()
    expect(html).toContain('ArrowRight')
    expect(html).toContain('ArrowLeft')
  })

  it('retains OTP / 2FA multi-step chaining', () => {
    const html = render()
    expect(html).toContain('otp_required')
    expect(html).toContain('password_required')
    expect(html).toContain('showStepInput')
    expect(html).toContain('/otp')
  })

  it('follows redirect_url on success', () => {
    expect(render()).toContain('window.location.replace(pendingRedirectUrl)')
  })

  it('lands prefill in the matching tab field', () => {
    expect(render({ prefill: { TELEGRAM_PHONE: '+84900000000' } })).toContain('value="+84900000000"')
  })

  it('escapes user-supplied tab values', () => {
    const html = renderCredentialForm(
      {
        server: 's',
        displayName: 'S',
        tabs: [
          {
            id: 'x',
            label: '<script>alert(1)</script>',
            fields: [{ key: 'K', label: '<img src=x onerror=alert(1)>', type: 'text' }]
          }
        ]
      },
      { submitUrl: '/a' }
    )
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).not.toContain('<img src=x')
    expect(html).toContain('&lt;script&gt;')
  })

  it('opts in the username field', () => {
    const html = render({ includeUsernameField: true })
    expect((html.match(/name="__sub_username"/g) ?? []).length).toBe(1)
  })

  it('uses safe DOM methods', () => {
    const html = render()
    expect(html).toContain('createElement')
    expect(html).toContain('textContent')
  })
})
