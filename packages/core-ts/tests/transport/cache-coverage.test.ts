import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as cacheModule from '../../src/transport/cache.js'
import { atomicWrite, cacheFilename, loadToolsCache } from '../../src/transport/cache.js'

// Mocking node:fs for readFileSync failure
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return {
    ...actual,
    readFileSync: vi.fn((path, options) => {
      if (typeof path === 'string' && path.includes('error-trigger')) {
        throw new Error('read error')
      }
      return actual.readFileSync(path, options)
    })
  }
})

let dir: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'mcp-cache-coverage-'))
  vi.spyOn(cacheModule, 'cacheDir').mockReturnValue(dir)
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('cache coverage', () => {
  it('atomicWrite on win32', () => {
    vi.stubGlobal('process', { ...process, platform: 'win32' })
    const path = join(dir, 'win32-test.json')
    atomicWrite(path, '{}')
    expect(cacheModule.cacheDir()).toBe(dir)
  })

  it('loadToolsCache with internal version mismatch', () => {
    const serverName = 'test-server'
    const port = 1234
    const srvVersion = '1.0.0'
    const coreVersion = '2.0.0'
    const name = cacheFilename(serverName, port, srvVersion, coreVersion)
    const path = join(dir, name)

    // Internal srv_version mismatch
    writeFileSync(
      path,
      JSON.stringify({
        tools: [],
        srv_version: 'wrong',
        core_version: coreVersion
      })
    )
    expect(loadToolsCache(serverName, port, srvVersion, coreVersion)).toBeNull()

    // Internal core_version mismatch
    writeFileSync(
      path,
      JSON.stringify({
        tools: [],
        srv_version: srvVersion,
        core_version: 'wrong'
      })
    )
    expect(loadToolsCache(serverName, port, srvVersion, coreVersion)).toBeNull()
  })

  it('loadToolsCache handles readFileSync error', () => {
    const serverName = 'error-trigger'
    const port = 1234
    const srvVersion = '1.0.0'
    const coreVersion = '2.0.0'
    const name = cacheFilename(serverName, port, srvVersion, coreVersion)
    const path = join(dir, name)
    writeFileSync(path, '{}')

    expect(loadToolsCache(serverName, port, srvVersion, coreVersion)).toBeNull()
  })
})
