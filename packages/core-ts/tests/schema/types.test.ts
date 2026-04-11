import { describe, expect, it } from 'vitest'
import type {
  ConfigField,
  ConfigMode,
  CredentialsRoute,
  DynamicFlow,
  OAuthRoute,
  RelayConfigSchema
} from '../../src/schema/types.js'

describe('schema/types', () => {
  it('should type-check a simple fields schema (Telegram example)', () => {
    const schema: RelayConfigSchema = {
      server: 'telegram',
      displayName: 'Telegram MCP',
      fields: [
        {
          key: 'api_id',
          label: 'API ID',
          type: 'text',
          placeholder: '12345678',
          helpUrl: 'https://my.telegram.org/apps',
          helpText: 'Get your API ID from my.telegram.org',
          required: true,
          validation: '^\\d+$'
        },
        {
          key: 'api_hash',
          label: 'API Hash',
          type: 'password',
          required: true
        },
        {
          key: 'phone',
          label: 'Phone Number',
          type: 'tel',
          placeholder: '+1234567890',
          required: true
        }
      ]
    }
    expect(schema.server).toBe('telegram')
    expect(schema.fields).toHaveLength(3)
    expect(schema.modes).toBeUndefined()
    expect(schema.dynamicFlow).toBeUndefined()
  })

  it('should type-check a modes schema', () => {
    const schema: RelayConfigSchema = {
      server: 'slack',
      displayName: 'Slack MCP',
      modes: [
        {
          id: 'bot',
          label: 'Bot Token',
          description: 'Use a Slack Bot token',
          fields: [{ key: 'bot_token', label: 'Bot Token', type: 'password', required: true }]
        },
        {
          id: 'user',
          label: 'User Token',
          description: 'Use a Slack User token',
          fields: [{ key: 'user_token', label: 'User Token', type: 'password', required: true }]
        }
      ]
    }
    expect(schema.modes).toHaveLength(2)
    expect(schema.modes?.[0].id).toBe('bot')
  })

  it('should type-check a dynamicFlow schema (Email example)', () => {
    const entryField: ConfigField = {
      key: 'provider',
      label: 'Email Provider',
      type: 'select',
      choices: ['gmail', 'outlook', 'custom'],
      required: true
    }

    const oauthRoute: OAuthRoute = {
      match: ['gmail'],
      action: 'oauth2_device_code',
      message: 'Sign in with Google',
      oauthConfig: {
        clientId: 'xxx.apps.googleusercontent.com',
        scopes: ['https://mail.google.com/']
      }
    }

    const credentialsRoute: CredentialsRoute = {
      match: ['custom'],
      action: 'credentials',
      fields: [
        { key: 'smtp_host', label: 'SMTP Host', type: 'text', required: true },
        { key: 'smtp_port', label: 'SMTP Port', type: 'number', default: '587' },
        { key: 'username', label: 'Username', type: 'email', required: true },
        { key: 'password', label: 'Password', type: 'password', required: true }
      ]
    }

    const flow: DynamicFlow = {
      entryField,
      routes: [oauthRoute, credentialsRoute]
    }

    const schema: RelayConfigSchema = {
      server: 'email',
      displayName: 'Email MCP',
      dynamicFlow: flow
    }

    expect(schema.dynamicFlow).toBeDefined()
    expect(schema.dynamicFlow?.routes).toHaveLength(2)
    expect(schema.dynamicFlow?.routes[0].action).toBe('oauth2_device_code')
    expect(schema.dynamicFlow?.routes[1].action).toBe('credentials')
  })

  it('should type-check optional fields', () => {
    const schema: RelayConfigSchema = {
      server: 'notion',
      displayName: 'Notion MCP',
      fields: [{ key: 'token', label: 'Integration Token', type: 'password', required: true }],
      optional: [{ key: 'workspace_id', label: 'Workspace ID', type: 'text', helpText: 'Optional filter' }]
    }
    expect(schema.optional).toHaveLength(1)
    expect(schema.optional?.[0].required).toBeUndefined()
  })

  it('should type-check ConfigMode interface', () => {
    const mode: ConfigMode = {
      id: 'api_key',
      label: 'API Key',
      description: 'Authenticate with an API key',
      fields: [{ key: 'api_key', label: 'API Key', type: 'password', required: true }]
    }
    expect(mode.id).toBe('api_key')
    expect(mode.fields).toHaveLength(1)
  })
})
