/**
 * Tests for the version-keyed tools cache (D10) — TS parity with core-py.
 *
 * Cache filename includes both server version and core version, so an upgrade
 * on either side invalidates the cache. ``persistToolsCache`` must not throw
 * on filesystem errors (root cause for crg #384, where a Windows write
 * failure crashed the bridge).
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import * as cacheModule from '../../src/transport/cache.js'
import { cacheDir, cacheFilename, loadToolsCache, persistToolsCache } from '../../src/transport/cache.js'

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

  it('cacheDir returns a string', () => {
    vi.restoreAllMocks()
    const path = cacheDir()
    expect(typeof path).toBe('string')
    expect(path.length).toBeGreaterThan(0)
  })

  it('loadToolsCache returns null on missing file', () => {
    expect(loadToolsCache('missing', 0, '1.0.0', '1.0.0')).toBeNull()
  })

  it('loadToolsCache returns null on invalid JSON', () => {
    const path = join(dir, cacheFilename('bad-json', 0, '1.0.0', '1.0.0'))
    writeFileSync(path, 'not json')
    expect(loadToolsCache('bad-json', 0, '1.0.0', '1.0.0')).toBeNull()
  })

  it('loadToolsCache returns null if tools is not an array', () => {
    const path = join(dir, cacheFilename('not-array', 0, '1.0.0', '1.0.0'))
    writeFileSync(path, JSON.stringify({ tools: 'not an array', srvVersion: '1.0.0', coreVersion: '1.0.0' }))
    expect(loadToolsCache('not-array', 0, '1.0.0', '1.0.0')).toBeNull()
  })

  it('persistToolsCache creates directory if missing', () => {
    const nestedDir = join(dir, 'nested', 'cache')
    vi.spyOn(cacheModule, 'cacheDir').mockReturnValue(nestedDir)
    const tools = [{ name: 'test' }]
    persistToolsCache('nested-mcp', 123, '1.0.0', '1.0.0', tools)
    expect(loadToolsCache('nested-mcp', 123, '1.0.0', '1.0.0')).toEqual(tools)
  })
})
