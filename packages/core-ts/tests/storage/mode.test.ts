import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { readConfig, setConfigPath, writeConfig } from '../../src/storage/config-file.js'
import { clearMode, getMode, setLocalMode } from '../../src/storage/mode.js'

let tempDir: string

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'mcp-mode-test-'))
  setConfigPath(join(tempDir, 'config.enc'))
})

afterEach(async () => {
  setConfigPath(null)
  await rm(tempDir, { recursive: true, force: true })
})

describe('setLocalMode', () => {
  it('writes mode marker', async () => {
    await setLocalMode('test-server')

    const config = await readConfig('test-server')
    expect(config).not.toBeNull()
    expect(config?._mode).toBe('local')
  }, 60000)

  it('overwrites existing config', async () => {
    await writeConfig('test-server', { api_key: 'secret123' })
    await setLocalMode('test-server')

    const config = await readConfig('test-server')
    expect(config).toEqual({ _mode: 'local' })
  }, 60000)
})

describe('getMode', () => {
  it('returns null when no config', async () => {
    const result = await getMode('test-server')
    expect(result).toBeNull()
  }, 60000)

  it('returns local when local mode set', async () => {
    await setLocalMode('test-server')
    const result = await getMode('test-server')
    expect(result).toBe('local')
  }, 60000)

  it('returns configured when has real keys', async () => {
    await writeConfig('test-server', { api_key: 'key123', base_url: 'https://api' })
    const result = await getMode('test-server')
    expect(result).toBe('configured')
  }, 60000)

  it('returns configured with mixed keys', async () => {
    await writeConfig('test-server', { _mode: 'something-else', api_key: 'key123' })
    const result = await getMode('test-server')
    expect(result).toBe('configured')
  }, 60000)

  it('returns null with empty mode value', async () => {
    await writeConfig('test-server', { _mode: 'unknown' })
    const result = await getMode('test-server')
    // Has _mode but not "local", and no other keys
    expect(result).toBeNull()
  }, 60000)
})

describe('clearMode', () => {
  it('removes config entry', async () => {
    await setLocalMode('test-server')
    expect(await getMode('test-server')).toBe('local')

    await clearMode('test-server')
    expect(await getMode('test-server')).toBeNull()
  }, 60000)

  it('removes configured entry', async () => {
    await writeConfig('test-server', { api_key: 'key123' })
    expect(await getMode('test-server')).toBe('configured')

    await clearMode('test-server')
    expect(await getMode('test-server')).toBeNull()
  }, 60000)

  it('no error when no config', async () => {
    // Should not throw
    await clearMode('nonexistent-server')
  }, 60000)
})

describe('mode independence', () => {
  it('different servers have independent modes', async () => {
    await setLocalMode('server-a')
    await writeConfig('server-b', { api_key: 'key' })

    expect(await getMode('server-a')).toBe('local')
    expect(await getMode('server-b')).toBe('configured')
    expect(await getMode('server-c')).toBeNull()
  }, 60000)

  it('clearing one server does not affect others', async () => {
    await setLocalMode('server-a')
    await setLocalMode('server-b')

    await clearMode('server-a')

    expect(await getMode('server-a')).toBeNull()
    expect(await getMode('server-b')).toBe('local')
  }, 60000)
})
