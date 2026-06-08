/**
 * Tests for the version-keyed tools cache (D10) — TS parity with core-py.
 *
 * Cache filename includes both server version and core version, so an upgrade
 * on either side invalidates the cache. ``persistToolsCache`` must not throw
 * on filesystem errors (root cause for crg #384, where a Windows write
 * failure crashed the bridge).
 */

import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import * as cacheModule from '../../src/transport/cache.js'
import { atomicWrite, cacheDir, cacheFilename, loadToolsCache, persistToolsCache } from '../../src/transport/cache.js'

// Mock node:fs to allow spying on its exports
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return {
    ...actual,
    chmodSync: vi.fn(actual.chmodSync),
    readFileSync: vi.fn(actual.readFileSync)
  }
})

let dir: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'mcp-cache-'))
  vi.spyOn(cacheModule, 'cacheDir').mockReturnValue(dir)
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('tools cache', () => {
  it('cacheDir returns home-based path', () => {
    vi.restoreAllMocks() // Use real implementation
    const expected = join(homedir(), '.config', 'mcp', 'cache')
    expect(cacheDir()).toBe(expected)
  })

  it('filename includes versions', () => {
    expect(cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')).toBe('wet-mcp-55317-2.28.4-1.11.0.tools.json')
  })

  it('persist + load match', () => {
    const tools = [{ name: 'search' }]
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', tools)
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toEqual(tools)
  })

  it('mismatched srv_version in filename returns null', () => {
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [{ name: 'search' }])
    expect(loadToolsCache('wet-mcp', 55317, '2.29.0', '1.11.0')).toBeNull()
  })

  it('mismatched core_version in filename returns null', () => {
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [{ name: 'search' }])
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.12.0')).toBeNull()
  })

  it('load returns null on content version mismatch', () => {
    const name = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, name)
    // Case 1: srvVersion mismatch
    writeFileSync(path, JSON.stringify({ tools: [], srvVersion: '2.29.0', coreVersion: '1.11.0' }))
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()

    // Case 2: coreVersion mismatch
    writeFileSync(path, JSON.stringify({ tools: [], srvVersion: '2.28.4', coreVersion: '1.12.0' }))
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('load returns null on invalid JSON', () => {
    const name = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, name)
    writeFileSync(path, 'not-json')
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('load returns null when readFileSync throws', () => {
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [{ name: 'search' }])
    vi.mocked(readFileSync).mockImplementationOnce(() => {
      throw new Error('read failure')
    })
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('load returns null when payload is null', () => {
    const name = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, name)
    writeFileSync(path, 'null')
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('load returns null when tools is not an array', () => {
    const name = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, name)
    writeFileSync(path, JSON.stringify({ tools: 'not-array', srvVersion: '2.28.4', coreVersion: '1.11.0' }))
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('atomicWrite creates directory if missing', () => {
    const nestedDir = join(dir, 'nested', 'dir')
    const path = join(nestedDir, 'test.json')
    atomicWrite(path, '{}')
    expect(existsSync(path)).toBe(true)
  })

  it('atomicWrite skips chmod on win32', () => {
    vi.stubGlobal('process', { ...process, platform: 'win32' })
    const path = join(dir, 'win32-test.json')
    vi.mocked(chmodSync).mockClear()
    atomicWrite(path, '{}')
    expect(existsSync(path)).toBe(true)
    expect(chmodSync).not.toHaveBeenCalled()
  })

  it('atomic replace existing', () => {
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [{ name: 'a' }])
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [{ name: 'b' }])
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toEqual([{ name: 'b' }])
  })

  it('persist suppresses error', () => {
    vi.spyOn(cacheModule, 'atomicWrite').mockImplementation(() => {
      throw new Error('access denied')
    })
    expect(() => persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [])).not.toThrow()
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('atomicWrite handles chmod error', () => {
    vi.stubGlobal('process', { ...process, platform: 'linux' })
    vi.mocked(chmodSync).mockImplementationOnce(() => {
      throw new Error('chmod failed')
    })
    const path = join(dir, 'chmod-err.json')
    expect(() => atomicWrite(path, '{}')).not.toThrow()
    expect(existsSync(path)).toBe(true)
  })
})
