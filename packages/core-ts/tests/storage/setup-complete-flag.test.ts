import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import {
  clearKeyCacheForTesting,
  markSetupComplete,
  readConfig,
  SETUP_COMPLETE_KEY,
  setConfigPath,
  writeConfig
} from '../../src/storage/config-file.js'

let configDir: string

beforeEach(() => {
  configDir = mkdtempSync(join(tmpdir(), 'mcp-core-setup-complete-'))
  setConfigPath(join(configDir, 'config.enc'))
  clearKeyCacheForTesting()
})

afterEach(() => {
  setConfigPath(null)
  clearKeyCacheForTesting()
  rmSync(configDir, { recursive: true, force: true })
})

describe('setup-complete flag', () => {
  it('SETUP_COMPLETE_KEY constant is "_setup_complete"', () => {
    expect(SETUP_COMPLETE_KEY).toBe('_setup_complete')
  })

  it('markSetupComplete sets the flag without losing other keys', async () => {
    await writeConfig('demo', { API_KEY: 'k' })
    await markSetupComplete('demo')
    const saved = await readConfig('demo')
    expect(saved).not.toBeNull()
    expect(saved?.[SETUP_COMPLETE_KEY]).toBe('true')
    expect(saved?.API_KEY).toBe('k')
  })

  it('markSetupComplete works when no prior config exists', async () => {
    await markSetupComplete('demo')
    const saved = await readConfig('demo')
    expect(saved).toEqual({ [SETUP_COMPLETE_KEY]: 'true' })
  })

  it('writeConfig does not auto-carry-forward the flag', async () => {
    await writeConfig('demo', { API_KEY: 'k1', [SETUP_COMPLETE_KEY]: 'true' })
    await writeConfig('demo', { API_KEY: 'k2' })
    const saved = await readConfig('demo')
    expect(saved?.[SETUP_COMPLETE_KEY]).toBeUndefined()
    expect(saved?.API_KEY).toBe('k2')
  })

  it('markSetupComplete is idempotent', async () => {
    await writeConfig('demo', { API_KEY: 'k' })
    await markSetupComplete('demo')
    await markSetupComplete('demo')
    const saved = await readConfig('demo')
    expect(saved).toEqual({ API_KEY: 'k', [SETUP_COMPLETE_KEY]: 'true' })
  })

  it('markSetupComplete does not pollute other servers', async () => {
    await writeConfig('server-a', { A: '1' })
    await writeConfig('server-b', { B: '2' })
    await markSetupComplete('server-a')
    expect(await readConfig('server-a')).toEqual({ A: '1', [SETUP_COMPLETE_KEY]: 'true' })
    expect(await readConfig('server-b')).toEqual({ B: '2' })
  })
})
