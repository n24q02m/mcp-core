import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { setConfigPath, writeConfig } from '../../src/storage/config-file.js'
import { resolveConfig } from '../../src/storage/resolver.js'

let tempDir: string

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'mcp-resolver-test-'))
  setConfigPath(join(tempDir, 'config.enc'))
})

afterEach(async () => {
  setConfigPath(null)
  // Clean env vars
  for (const key of Object.keys(process.env)) {
    if (key.startsWith('MCP_')) {
      delete process.env[key]
    }
  }
  await rm(tempDir, { recursive: true, force: true })
})

describe('resolveConfig', () => {
  it('env vars take highest priority', async () => {
    process.env.MCP_TELEGRAM_BOT_TOKEN = 'env-token'
    process.env.MCP_TELEGRAM_CHAT_ID = 'env-chat'

    // Also write to config file (should be ignored)
    await writeConfig('telegram', { bot_token: 'file-token', chat_id: 'file-chat' })

    const result = await resolveConfig('telegram', ['bot_token', 'chat_id'])
    expect(result.source).toBe('env')
    expect(result.config).toEqual({ bot_token: 'env-token', chat_id: 'env-chat' })
  })

  it('falls back to config file when env vars incomplete', async () => {
    process.env.MCP_TELEGRAM_BOT_TOKEN = 'env-token'
    // chat_id NOT set in env

    await writeConfig('telegram', { bot_token: 'file-token', chat_id: 'file-chat' })

    const result = await resolveConfig('telegram', ['bot_token', 'chat_id'])
    expect(result.source).toBe('file')
    expect(result.config).toEqual({ bot_token: 'file-token', chat_id: 'file-chat' })
  })

  it('falls back to defaults when file config incomplete', async () => {
    await writeConfig('telegram', { bot_token: 'file-token' })
    // file missing chat_id

    const defaults = { bot_token: 'def-token', chat_id: 'def-chat' }
    const result = await resolveConfig('telegram', ['bot_token', 'chat_id'], defaults)
    expect(result.source).toBe('defaults')
    expect(result.config).toEqual(defaults)
  })

  it('returns null when nothing found', async () => {
    const result = await resolveConfig('telegram', ['bot_token', 'chat_id'])
    expect(result.source).toBeNull()
    expect(result.config).toBeNull()
  })

  it('returns null when defaults incomplete', async () => {
    const result = await resolveConfig('telegram', ['bot_token', 'chat_id'], { bot_token: 'partial' })
    expect(result.source).toBeNull()
    expect(result.config).toBeNull()
  })

  it('handles hyphenated server names in env var lookup', async () => {
    process.env.MCP_MY_SERVER_API_KEY = 'key123'

    const result = await resolveConfig('my-server', ['api_key'])
    expect(result.source).toBe('env')
    expect(result.config).toEqual({ api_key: 'key123' })
  })

  it('empty env var is treated as missing', async () => {
    process.env.MCP_TELEGRAM_BOT_TOKEN = ''

    const result = await resolveConfig('telegram', ['bot_token'])
    expect(result.source).toBeNull()
    expect(result.config).toBeNull()
  })

  it('file config with empty value is treated as missing', async () => {
    await writeConfig('telegram', { bot_token: '' })

    const result = await resolveConfig('telegram', ['bot_token'])
    expect(result.source).toBeNull()
    expect(result.config).toBeNull()
  })
})
