import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  clearKeyCacheForTesting,
  readConfig as readLegacyConfig,
  SETUP_COMPLETE_KEY,
  setConfigPath,
  writeConfig as writeLegacyConfig
} from '../../src/storage/config-file.js'
import {
  deleteStoredConfig,
  markSetupComplete,
  pluginNameForServer,
  readStoredConfig,
  writeStoredConfig
} from '../../src/storage/credential-store.js'
import { PerPluginStore, setHomeDirForTesting } from '../../src/storage/per-plugin-store.js'

// The unified single-user credential router persists to PerPluginStore (keyed
// by the plugin slug) with a READ fallback to the legacy shared config.enc
// (keyed by the console name). Tests isolate BOTH stores into one temp home:
// setHomeDirForTesting redirects PerPluginStore's LocalFsBackend + machine key,
// setConfigPath redirects the legacy config.enc.
let home: string

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'cred-store-'))
  setHomeDirForTesting(home)
  setConfigPath(join(home, 'config.enc'))
  clearKeyCacheForTesting()
})

afterEach(() => {
  setHomeDirForTesting(null)
  setConfigPath(null)
  clearKeyCacheForTesting()
  rmSync(home, { recursive: true, force: true })
})

describe('pluginNameForServer', () => {
  it('strips a trailing -mcp suffix (matches buildCli + core-py slug)', () => {
    expect(pluginNameForServer('better-email-mcp')).toBe('better-email')
    expect(pluginNameForServer('better-notion-mcp')).toBe('better-notion')
    expect(pluginNameForServer('wet-mcp')).toBe('wet')
  })

  it('is a no-op for a name without the -mcp suffix', () => {
    expect(pluginNameForServer('telegram')).toBe('telegram')
    expect(pluginNameForServer('some-server')).toBe('some-server')
  })
})

describe('writeStoredConfig + readStoredConfig (round-trip via PerPluginStore)', () => {
  it('writes to the per-plugin store, not the legacy config.enc', async () => {
    await writeStoredConfig('better-email-mcp', { EMAIL_CREDENTIALS: 'a@b.com:pw' })

    // Round-trips through the unified reader.
    expect(await readStoredConfig('better-email-mcp')).toEqual({ EMAIL_CREDENTIALS: 'a@b.com:pw' })
    // Lands in the plugin-slug store the CLI (buildCli config/doctor) reads.
    expect(await new PerPluginStore('better-email').load()).toEqual({ EMAIL_CREDENTIALS: 'a@b.com:pw' })
    // Does NOT touch the legacy shared config.enc.
    expect(await readLegacyConfig('better-email-mcp')).toBeNull()
  })

  it('honors an explicit pluginName override (telegram-style slug)', async () => {
    await writeStoredConfig('better-telegram-mcp', { BOT_TOKEN: 't' }, 'telegram')
    expect(await new PerPluginStore('telegram').load()).toEqual({ BOT_TOKEN: 't' })
    expect(await readStoredConfig('better-telegram-mcp', 'telegram')).toEqual({ BOT_TOKEN: 't' })
  })

  it('returns null when neither store has the config', async () => {
    expect(await readStoredConfig('never-configured-mcp')).toBeNull()
  })
})

describe('legacy config.enc fallback (ZERO data-loss / zero re-auth)', () => {
  it('reads an existing config.enc entry when the per-plugin store is empty', async () => {
    // Simulate a credential written by the OLD path (config-file writeConfig).
    await writeLegacyConfig('better-notion-mcp', { NOTION_TOKEN: 'secret-abc' })

    // Per-plugin store is empty; the unified reader falls back to legacy.
    expect(await new PerPluginStore('better-notion').load()).toBeNull()
    expect(await readStoredConfig('better-notion-mcp')).toEqual({ NOTION_TOKEN: 'secret-abc' })
  })

  it('prefers the per-plugin store over legacy when both exist', async () => {
    await writeLegacyConfig('better-notion-mcp', { NOTION_TOKEN: 'legacy' })
    await writeStoredConfig('better-notion-mcp', { NOTION_TOKEN: 'store' })

    expect(await readStoredConfig('better-notion-mcp')).toEqual({ NOTION_TOKEN: 'store' })
  })
})

describe('migrate-on-write', () => {
  it('moves credentials to the per-plugin store on the next write', async () => {
    // Existing legacy credential, readable via fallback.
    await writeLegacyConfig('better-notion-mcp', { NOTION_TOKEN: 'old' })
    expect(await readStoredConfig('better-notion-mcp')).toEqual({ NOTION_TOKEN: 'old' })

    // Reconfigure: the write lands in the per-plugin store.
    await writeStoredConfig('better-notion-mcp', { NOTION_TOKEN: 'new' })

    expect(await new PerPluginStore('better-notion').load()).toEqual({ NOTION_TOKEN: 'new' })
    // The unified reader now serves the migrated value.
    expect(await readStoredConfig('better-notion-mcp')).toEqual({ NOTION_TOKEN: 'new' })
  })
})

describe('deleteStoredConfig (clears BOTH stores)', () => {
  it('removes the credential from the per-plugin store AND the legacy config.enc', async () => {
    await writeLegacyConfig('better-email-mcp', { EMAIL_CREDENTIALS: 'legacy' })
    await writeStoredConfig('better-email-mcp', { EMAIL_CREDENTIALS: 'store' })

    await deleteStoredConfig('better-email-mcp')

    expect(await new PerPluginStore('better-email').load()).toBeNull()
    expect(await readLegacyConfig('better-email-mcp')).toBeNull()
    expect(await readStoredConfig('better-email-mcp')).toBeNull()
  })

  it('does not throw when nothing is stored', async () => {
    await expect(deleteStoredConfig('never-configured-mcp')).resolves.toBeUndefined()
  })
})

describe('markSetupComplete', () => {
  it('sets the flag in the per-plugin store without dropping existing keys', async () => {
    await writeStoredConfig('better-email-mcp', { EMAIL_CREDENTIALS: 'x' })
    await markSetupComplete('better-email-mcp')

    const saved = await new PerPluginStore('better-email').load()
    expect(saved?.EMAIL_CREDENTIALS).toBe('x')
    expect(saved?.[SETUP_COMPLETE_KEY]).toBe('true')
  })

  it('creates a store entry with just the flag when nothing exists', async () => {
    await markSetupComplete('better-email-mcp')
    expect(await new PerPluginStore('better-email').load()).toEqual({ [SETUP_COMPLETE_KEY]: 'true' })
  })

  it('migrates an existing legacy config to the per-plugin store, adding the flag', async () => {
    await writeLegacyConfig('better-email-mcp', { EMAIL_CREDENTIALS: 'legacy-cred' })
    await markSetupComplete('better-email-mcp')

    expect(await new PerPluginStore('better-email').load()).toEqual({
      EMAIL_CREDENTIALS: 'legacy-cred',
      [SETUP_COMPLETE_KEY]: 'true'
    })
  })
})

describe('cross-server isolation', () => {
  it('keeps single-user credentials for different servers independent', async () => {
    await writeStoredConfig('better-email-mcp', { EMAIL_CREDENTIALS: 'e' })
    await writeStoredConfig('better-notion-mcp', { NOTION_TOKEN: 'n' })

    expect(await readStoredConfig('better-email-mcp')).toEqual({ EMAIL_CREDENTIALS: 'e' })
    expect(await readStoredConfig('better-notion-mcp')).toEqual({ NOTION_TOKEN: 'n' })

    await deleteStoredConfig('better-email-mcp')
    expect(await readStoredConfig('better-email-mcp')).toBeNull()
    expect(await readStoredConfig('better-notion-mcp')).toEqual({ NOTION_TOKEN: 'n' })
  })
})
