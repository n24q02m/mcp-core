/**
 * Tests for the version-keyed tools cache (D10) — TS parity with core-py.
 *
 * Cache filename includes both server version and core version, so an upgrade
 * on either side invalidates the cache. ``persistToolsCache`` must not throw
 * on filesystem errors (root cause for crg #384, where a Windows write
 * failure crashed the bridge).
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import * as cacheModule from '../../src/transport/cache.js'
import { atomicWrite, cacheDir, cacheFilename, loadToolsCache, persistToolsCache } from '../../src/transport/cache.js'

describe('cacheDir', () => {
  it('returns default path', () => {
    const path = cacheDir()
    expect(path).toContain('.config')
    expect(path).toContain('mcp')
    expect(path).toContain('cache')
  })
})

describe('cacheFilename', () => {
  it('includes versions', () => {
    expect(cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')).toBe('wet-mcp-55317-2.28.4-1.11.0.tools.json')
  })

  it('handles empty strings', () => {
    expect(cacheFilename('', 0, '', '')).toBe('-0--.tools.json')
  })

  it('handles special characters', () => {
    expect(cacheFilename('my@server', 80, '1.0.0-beta', 'v2')).toBe('my@server-80-1.0.0-beta-v2.tools.json')
  })
})

describe('tools cache', () => {
  let dir: string

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'mcp-cache-'))
    vi.spyOn(cacheModule, 'cacheDir').mockReturnValue(dir)
  })

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
    vi.restoreAllMocks()
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

  it('loadToolsCache returns null on malformed JSON', () => {
    const filename = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, filename)
    writeFileSync(path, 'not-json')
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('loadToolsCache returns null if tools is not an array', () => {
    const filename = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, filename)
    writeFileSync(
      path,
      JSON.stringify({
        srvVersion: '2.28.4',
        coreVersion: '1.11.0',
        tools: 'not-an-array'
      })
    )
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('atomicWrite creates missing directories', () => {
    const nestedDir = join(dir, 'nested', 'deeply')
    const path = join(nestedDir, 'test.json')
    atomicWrite(path, '{"ok":true}')
    expect(JSON.parse(readFileSync(path, 'utf-8'))).toEqual({ ok: true })
  })
})
