import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  clearKeyCacheForTesting,
  deleteConfig,
  exportConfig,
  importConfig,
  listConfigs,
  readConfig,
  setConfigPath,
  writeConfig
} from '../../src/storage/config-file.js'

let tempDir: string

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'mcp-test-'))
  setConfigPath(join(tempDir, 'config.enc'))
  clearKeyCacheForTesting()
})

afterEach(async () => {
  setConfigPath(null)
  await rm(tempDir, { recursive: true, force: true })
})

describe('writeConfig + readConfig', () => {
  it('writes and reads a server config', async () => {
    await writeConfig('telegram', { botToken: 'abc123', chatId: '456' })
    const config = await readConfig('telegram')
    expect(config).toEqual({ botToken: 'abc123', chatId: '456' })
  })

  it('returns null for non-existent server', async () => {
    const config = await readConfig('nonexistent')
    expect(config).toBeNull()
  })

  it('returns null when no config file exists', async () => {
    const config = await readConfig('anything')
    expect(config).toBeNull()
  })
})

describe('writeConfig merging', () => {
  it('does not overwrite other servers sections', async () => {
    await writeConfig('telegram', { botToken: 'tok1' })
    await writeConfig('slack', { webhook: 'https://example.com' })

    const telegram = await readConfig('telegram')
    const slack = await readConfig('slack')
    expect(telegram).toEqual({ botToken: 'tok1' })
    expect(slack).toEqual({ webhook: 'https://example.com' })
  })

  it('overwrites same server config on second write', async () => {
    await writeConfig('telegram', { botToken: 'old' })
    await writeConfig('telegram', { botToken: 'new', extra: 'field' })

    const config = await readConfig('telegram')
    expect(config).toEqual({ botToken: 'new', extra: 'field' })
  })
})

describe('deleteConfig', () => {
  it('removes a server section', async () => {
    await writeConfig('telegram', { botToken: 'tok' })
    await writeConfig('slack', { webhook: 'url' })

    await deleteConfig('telegram')

    expect(await readConfig('telegram')).toBeNull()
    expect(await readConfig('slack')).toEqual({ webhook: 'url' })
  })

  it('deletes file when last server removed', async () => {
    await writeConfig('telegram', { botToken: 'tok' })
    await deleteConfig('telegram')

    const { existsSync } = await import('node:fs')
    expect(existsSync(join(tempDir, 'config.enc'))).toBe(false)
  })

  it('no-op for non-existent server', async () => {
    await writeConfig('telegram', { botToken: 'tok' })
    await deleteConfig('nonexistent')
    expect(await readConfig('telegram')).toEqual({ botToken: 'tok' })
  })
})

describe('listConfigs', () => {
  it('returns empty array when no config', async () => {
    expect(await listConfigs()).toEqual([])
  })

  it('returns list of server names', async () => {
    await writeConfig('telegram', { a: '1' })
    await writeConfig('slack', { b: '2' })
    await writeConfig('discord', { c: '3' })

    const names = await listConfigs()
    expect(names.sort()).toEqual(['discord', 'slack', 'telegram'])
  })
})

describe('exportConfig + importConfig', () => {
  it('roundtrip with passphrase', async () => {
    await writeConfig('telegram', { botToken: 'abc' })
    await writeConfig('slack', { webhook: 'url' })

    const exported = await exportConfig('my-secret-passphrase')
    expect(exported).toBeInstanceOf(Buffer)

    // Clear local config
    await deleteConfig('telegram')
    await deleteConfig('slack')
    expect(await listConfigs()).toEqual([])

    // Import back
    await importConfig('my-secret-passphrase', exported)
    expect(await readConfig('telegram')).toEqual({ botToken: 'abc' })
    expect(await readConfig('slack')).toEqual({ webhook: 'url' })
  }, 60000)

  it('wrong passphrase fails to import', async () => {
    await writeConfig('telegram', { botToken: 'abc' })
    const exported = await exportConfig('correct-pass')

    await expect(importConfig('wrong-pass', exported)).rejects.toThrow()
  }, 60000)

  it('import merges into existing config', async () => {
    await writeConfig('local-server', { key: 'local-val' })

    // Create export data from a separate config
    await writeConfig('remote-server', { key: 'remote-val' })
    const exported = await exportConfig('pass')

    // Remove remote, keep local
    await deleteConfig('remote-server')
    expect(await listConfigs()).toEqual(['local-server'])

    // Import should merge
    await importConfig('pass', exported)
    expect(await readConfig('local-server')).toEqual({ key: 'local-val' })
    expect(await readConfig('remote-server')).toEqual({ key: 'remote-val' })
  }, 60000)
})

describe('config validation', () => {
  it('throws on invalid version', async () => {
    const invalidStore = { version: 2, servers: {} }
    // Manually write an invalid file to test loadStore validation
    const { encryptData } = await import('../../src/storage/encryption.js')
    const { getMachineId, getUsername } = await import('../../src/storage/machine-id.js')
    const { deriveFileKey } = await import('../../src/storage/encryption.js')
    const { writeFile } = await import('node:fs/promises')

    const [machineId, username] = await Promise.all([getMachineId(), getUsername()])
    const key = await deriveFileKey(machineId, username)
    const encrypted = await encryptData(key, JSON.stringify(invalidStore))
    await writeFile(join(tempDir, 'config.enc'), encrypted)

    await expect(readConfig('any')).rejects.toThrow('Invalid config schema')
  })

  it('throws on invalid servers object', async () => {
    const invalidStore = { version: 1, servers: 'not-an-object' }
    const { encryptData } = await import('../../src/storage/encryption.js')
    const { getMachineId, getUsername } = await import('../../src/storage/machine-id.js')
    const { deriveFileKey } = await import('../../src/storage/encryption.js')
    const { writeFile } = await import('node:fs/promises')

    const [machineId, username] = await Promise.all([getMachineId(), getUsername()])
    const key = await deriveFileKey(machineId, username)
    const encrypted = await encryptData(key, JSON.stringify(invalidStore))
    await writeFile(join(tempDir, 'config.enc'), encrypted)

    await expect(readConfig('any')).rejects.toThrow('Invalid config schema')
  })

  it('throws on invalid server config (non-string value)', async () => {
    const invalidStore = { version: 1, servers: { bad: { key: 123 } } }
    const { encryptData } = await import('../../src/storage/encryption.js')
    const { getMachineId, getUsername } = await import('../../src/storage/machine-id.js')
    const { deriveFileKey } = await import('../../src/storage/encryption.js')
    const { writeFile } = await import('node:fs/promises')

    const [machineId, username] = await Promise.all([getMachineId(), getUsername()])
    const key = await deriveFileKey(machineId, username)
    const encrypted = await encryptData(key, JSON.stringify(invalidStore))
    await writeFile(join(tempDir, 'config.enc'), encrypted)

    await expect(readConfig('any')).rejects.toThrow('Invalid config schema')
  })
})
