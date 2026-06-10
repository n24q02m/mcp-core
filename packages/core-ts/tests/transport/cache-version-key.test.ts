/**
 * Tests for the version-keyed tools cache (D10) — TS parity with core-py.
 */

import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import * as cacheModule from '../../src/transport/cache.js'
import { atomicWrite, cacheDir, cacheFilename, loadToolsCache, persistToolsCache } from '../../src/transport/cache.js'

// Mock node:fs to allow spying on readFileSync and chmodSync
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return {
    ...actual,
    readFileSync: vi.fn(actual.readFileSync),
    chmodSync: vi.fn(actual.chmodSync)
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
  vi.stubGlobal('process', process)
})

describe('tools cache', () => {
  it('cacheDir returns home-based path', () => {
    vi.restoreAllMocks()
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

  it('internal version mismatch returns null', () => {
    const name = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, name)
    writeFileSync(path, JSON.stringify({ tools: [], srv_version: 'wrong', core_version: '1.11.0' }))
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('load returns null on invalid JSON', () => {
    const name = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, name)
    writeFileSync(path, 'not-json')
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
  })

  it('load returns null on read failure', () => {
    persistToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0', [])
    const mockRead = vi.mocked(readFileSync)
    mockRead.mockImplementationOnce(() => {
      throw new Error('read error')
    })
    expect(loadToolsCache('wet-mcp', 55317, '2.28.4', '1.11.0')).toBeNull()
    mockRead.mockRestore()
  })

  it('load returns null when tools is not an array', () => {
    const name = cacheFilename('wet-mcp', 55317, '2.28.4', '1.11.0')
    const path = join(dir, name)
    writeFileSync(path, JSON.stringify({ tools: 'not-array', srv_version: '2.28.4', core_version: '1.11.0' }))
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
    const mockChmod = vi.mocked(chmodSync)
    mockChmod.mockClear()
    atomicWrite(path, '{}')
    expect(mockChmod).not.toHaveBeenCalled()
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
