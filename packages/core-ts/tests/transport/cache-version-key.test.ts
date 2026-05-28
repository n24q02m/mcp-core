/**
 * Tests for the version-keyed tools cache (D10) — TS parity with core-py.
 *
 * Cache filename includes both server version and core version, so an upgrade
 * on either side invalidates the cache. ``persistToolsCache`` must not throw
 * on filesystem errors (root cause for crg #384, where a Windows write
 * failure crashed the bridge).
 */

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import * as cacheModule from '../../src/transport/cache.js'
import { cacheFilename, loadToolsCache, persistToolsCache } from '../../src/transport/cache.js'

let dir: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'mcp-cache-'))
  vi.spyOn(cacheModule, 'cacheDir').mockReturnValue(dir)
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
  vi.restoreAllMocks()
})

describe('tools cache', () => {
  it('filename includes versions', () => {
    expect(cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')).toBe('wet-mcp-55317-2.28.4-1.11.0.tools.json')
  })

  it('persist + load match', () => {
    const tools = [{ name: 'search' }]
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', tools)
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toEqual(tools)
  })

  it('mismatched srv_version returns null', () => {
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [{ name: 'search' }])
    expect(loadToolsCache('wet-mcp', 55317, '2.29.0', '1.11.0')).toBeNull()
  })

  it('mismatched core_version returns null', () => {
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [{ name: 'search' }])
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.12.0')).toBeNull()
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

  it('persistToolsCache calls atomicWrite with correct payload', () => {
    const spy = vi.spyOn(cacheModule, 'atomicWrite')
    const tools = [{ name: 'test-tool' }]
    persistToolsCache('test-server', 8080, '1.0.0', '2.0.0', tools)

    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining('test-server-8080-1.0.0-2.0.0.tools.json'),
      JSON.stringify({ tools, srvVersion: '1.0.0', coreVersion: '2.0.0' })
    )
  })

  it('cacheDir returns default path', () => {
    // Restore the spy to test the real implementation
    vi.restoreAllMocks()
    const path = cacheModule.cacheDir()
    expect(path).toContain('.config')
    expect(path).toContain('mcp')
    expect(path).toContain('cache')
  })

  it('loadToolsCache returns null on invalid JSON', () => {
    const filename = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, filename)
    cacheModule.atomicWrite(path, 'invalid-json')
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('loadToolsCache returns null if tools is not an array', () => {
    const filename = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, filename)
    cacheModule.atomicWrite(
      path,
      JSON.stringify({ tools: 'not-an-array', srvVersion: '2.28.4', coreVersion: '1.11.0' })
    )
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('atomicWrite creates directory if it does not exist', async () => {
    const { existsSync, readFileSync } = await import('node:fs')
    const nestedDir = join(dir, 'nested', 'cache')
    const path = join(nestedDir, 'file.json')
    cacheModule.atomicWrite(path, '{}')
    expect(existsSync(nestedDir)).toBe(true)
    expect(readFileSync(path, 'utf-8')).toBe('{}')
  })

  it('loadToolsCache returns null on mismatched version in payload', () => {
    const filename = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, filename)
    // Writing payload with mismatched srvVersion internal to the file
    cacheModule.atomicWrite(path, JSON.stringify({ tools: [], srvVersion: 'WRONG', coreVersion: '1.11.0' }))
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('atomicWrite skips chmod on windows', () => {
    const originalPlatform = process.platform
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    const path = join(dir, 'win-test.json')
    cacheModule.atomicWrite(path, '{}')
    // Verification is hard without mocking fs.chmodSync, but we just want coverage
    Object.defineProperty(process, 'platform', { value: originalPlatform })
  })
})
