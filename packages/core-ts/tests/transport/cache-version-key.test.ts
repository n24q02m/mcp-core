/**
 * Tests for the version-keyed tools cache (D10) — TS parity with core-py.
 *
 * Cache filename includes both server version and core version, so an upgrade
 * on either side invalidates the cache. ``persistToolsCache`` must not throw
 * on filesystem errors (root cause for crg #384, where a Windows write
 * failure crashed the bridge).
 */

import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import * as cacheModule from '../../src/transport/cache.js'
import { atomicWrite, cacheDir, cacheFilename, loadToolsCache, persistToolsCache } from '../../src/transport/cache.js'

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
  it('cacheDir returns home-based path', () => {
    vi.restoreAllMocks() // Use real implementation
    const expected = join(homedir(), '.config', 'mcp', 'cache')
    expect(cacheDir()).toBe(expected)
  })

  it('filename includes versions', () => {
    expect(cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')).toBe('wet-mcp-55317-2.28.4-1.11.0.tools.json')
  })

  it('filename sanitizes path traversal characters', () => {
    const malicious = '../../../etc/passwd'
    const filename = cacheFilename(malicious, 80, malicious, malicious)
    expect(filename).not.toContain('../')
    expect(filename).not.toContain('..\\')
    expect(filename).not.toContain('/')
    expect(filename).not.toContain('\\')
    expect(filename).toBe('.._.._.._etc_passwd-80-.._.._.._etc_passwd-.._.._.._etc_passwd.tools.json')
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

  it('load returns null on invalid JSON', () => {
    const name = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, name)
    writeFileSync(path, 'not-json')
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
})
