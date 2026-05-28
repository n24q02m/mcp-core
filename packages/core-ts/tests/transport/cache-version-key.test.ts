/**
 * Tests for the version-keyed tools cache (D10) — TS parity with core-py.
 *
 * Cache filename includes both server version and core version, so an upgrade
 * on either side invalidates the cache. ``persistToolsCache`` must not throw
 * on filesystem errors (root cause for crg #384, where a Windows write
 * failure crashed the bridge).
 */

import * as fs from 'node:fs'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import * as cacheModule from '../../src/transport/cache.js'
import { atomicWrite, cacheFilename, loadToolsCache, persistToolsCache } from '../../src/transport/cache.js'

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
})

describe('atomicWrite', () => {
  it('writes content and creates parent directory', () => {
    const filePath = join(dir, 'nested', 'file.txt')
    atomicWrite(filePath, 'hello world')
    expect(readFileSync(filePath, 'utf-8')).toBe('hello world')
  })

  it('overwrites existing file', () => {
    const filePath = join(dir, 'file.txt')
    atomicWrite(filePath, 'first')
    atomicWrite(filePath, 'second')
    expect(readFileSync(filePath, 'utf-8')).toBe('second')
  })

  if (process.platform !== 'win32') {
    it('sets file permissions to 0o600', () => {
      const filePath = join(dir, 'secret.txt')
      atomicWrite(filePath, 'secret')
      const stats = statSync(filePath)
      expect(stats.mode & 0o777).toBe(0o600)
    })

    it('handles chmodSync failure gracefully', () => {
      vi.spyOn(fs, 'chmodSync').mockImplementation(() => {
        throw new Error('chmod failed')
      })
      const filePath = join(dir, 'fail-chmod.txt')
      // Should not throw
      expect(() => atomicWrite(filePath, 'content')).not.toThrow()
      expect(readFileSync(filePath, 'utf-8')).toBe('content')
    })
  }
})
