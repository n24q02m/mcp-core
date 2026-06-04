/**
 * Tests for the version-keyed tools cache (D10) — TS parity with core-py.
 *
 * Cache filename includes both server version and core version, so an upgrade
 * on either side invalidates the cache. ``persistToolsCache`` must not throw
 * on filesystem errors (root cause for crg #384, where a Windows write
 * failure crashed the bridge).
 */

import * as fs from 'node:fs'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import * as path from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import * as cacheModule from '../../src/transport/cache.js'
import { atomicWrite, cacheFilename, loadToolsCache, persistToolsCache } from '../../src/transport/cache.js'

// Mock chmodSync to be able to spy on it and mock errors
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return {
    ...actual,
    chmodSync: vi.fn(actual.chmodSync)
  }
})

// Mock dirname to test falsy branch
vi.mock('node:path', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:path')>()
  return {
    ...actual,
    dirname: vi.fn(actual.dirname)
  }
})

let dir: string

beforeEach(() => {
  dir = mkdtempSync(`${fs.realpathSync(tmpdir())}/mcp-cache-`)
  vi.spyOn(cacheModule, 'cacheDir').mockReturnValue(dir)
  vi.mocked(fs.chmodSync).mockClear()
  vi.mocked(path.dirname).mockClear()
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
  vi.restoreAllMocks()
})

describe('tools cache', () => {
  it('cacheDir returns mcp config path', () => {
    vi.restoreAllMocks()
    const p = cacheModule.cacheDir()
    expect(p).toContain('.config')
    expect(p).toContain('mcp')
    expect(p).toContain('cache')
  })

  it('filename includes versions', () => {
    expect(cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')).toBe('wet-mcp-55317-2.28.4-1.11.0.tools.json')
  })

  it('persist + load match', () => {
    const tools = [{ name: 'search' }]
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', tools)
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toEqual(tools)
  })

  it('mismatched srvVersion returns null (via filename)', () => {
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [{ name: 'search' }])
    expect(loadToolsCache('wet-mcp', 55317, '2.29.0', '1.11.0')).toBeNull()
  })

  it('mismatched srvVersion in file content returns null', () => {
    const filename = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const p = path.join(dir, filename)
    writeFileSync(p, JSON.stringify({ tools: [], srvVersion: '1.0.0', coreVersion: '1.11.0' }))
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('mismatched coreVersion in file content returns null', () => {
    const filename = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const p = path.join(dir, filename)
    writeFileSync(p, JSON.stringify({ tools: [], srvVersion: '2.28.4', coreVersion: '1.0.0' }))
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('loadToolsCache returns null for non-array tools', () => {
    const p = path.join(dir, cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0'))
    writeFileSync(p, JSON.stringify({ tools: 'not-an-array', srvVersion: '2.28.4', coreVersion: '1.11.0' }))
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('loadToolsCache returns null for invalid JSON', () => {
    const p = path.join(dir, cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0'))
    writeFileSync(p, 'invalid-json')
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('atomic replace existing', () => {
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [{ name: 'a' }])
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [{ name: 'b' }])
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toEqual([{ name: 'b' }])
  })

  it('atomicWrite creates directory recursively', () => {
    const nested = path.join(dir, 'a', 'b', 'test.json')
    atomicWrite(nested, 'content')
    expect(readFileSync(nested, 'utf-8')).toBe('content')
  })

  it('atomicWrite handles falsy directory', () => {
    vi.mocked(path.dirname).mockReturnValueOnce('')
    const p = path.join(dir, 'falsy.json')
    atomicWrite(p, 'content')
    expect(readFileSync(p, 'utf-8')).toBe('content')
  })

  it('atomicWrite skips chmod on win32', () => {
    const originalPlatform = process.platform
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })

    vi.mocked(fs.chmodSync).mockClear()
    atomicWrite(path.join(dir, 'win.json'), 'win')

    expect(fs.chmodSync).not.toHaveBeenCalled()
    Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
  })

  it('atomicWrite ignores chmod errors on non-win32', () => {
    if (process.platform === 'win32') return

    vi.mocked(fs.chmodSync).mockImplementationOnce(() => {
      throw new Error('chmod failed')
    })

    expect(() => atomicWrite(path.join(dir, 'fail-chmod.json'), 'content')).not.toThrow()
    expect(readFileSync(path.join(dir, 'fail-chmod.json'), 'utf-8')).toBe('content')
  })

  it('persist suppresses error', () => {
    vi.spyOn(cacheModule, 'atomicWrite').mockImplementation(() => {
      throw new Error('access denied')
    })
    expect(() => persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [])).not.toThrow()
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })
})
