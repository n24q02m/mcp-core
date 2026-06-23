import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join, normalize, sep } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as cacheModule from '../../src/transport/cache.js'
import { atomicWrite, cacheDir, cacheFilename, loadToolsCache, persistToolsCache } from '../../src/transport/cache.js'

// Mocking node:fs for specific failure cases
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return {
    ...actual,
    readFileSync: vi.fn((path, options) => {
      if (typeof path === 'string' && path.includes('error-trigger')) {
        throw new Error('read error')
      }
      return actual.readFileSync(path, options)
    }),
    chmodSync: vi.fn((path, mode) => {
      if (typeof path === 'string' && path.includes('chmod-error-trigger')) {
        throw new Error('chmod error')
      }
      return actual.chmodSync(path, mode)
    })
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

describe('tools cache core functionality', () => {
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
    writeFileSync(path, JSON.stringify({ tools: 'not-array', srv_version: '2.28.4', core_version: '1.11.0' }))
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

describe('cache coverage edge cases', () => {
  it('atomicWrite on win32', () => {
    vi.stubGlobal('process', { ...process, platform: 'win32' })
    const path = join(dir, 'win32-test.json')
    atomicWrite(path, '{}')
    expect(cacheModule.cacheDir()).toBe(dir)
  })

  it('atomicWrite handles chmodSync failure', () => {
    if (process.platform === 'win32') return
    const path = join(dir, 'chmod-error-trigger.json')
    // atomicWrite will call chmodSync on the .tmp file
    expect(() => atomicWrite(path, '{}')).not.toThrow()
    expect(existsSync(path)).toBe(true)
  })

  it('loadToolsCache with internal version mismatch (detailed)', () => {
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

describe('cache path traversal and security', () => {
  it('sanitizes path traversal characters in filename', () => {
    const maliciousName = '../../etc/passwd'
    const filename = cacheFilename(maliciousName, 80, '1.0', '1.0')

    // It should no longer contain '/'
    expect(filename).not.toContain('/')
    expect(filename).not.toContain('\\')
    expect(filename).toBe('______etc_passwd-80-1.0-1.0.tools.json')

    const baseDir = normalize('/tmp/mcp-cache')
    const fullPath = normalize(join(baseDir, filename))

    // The resulting path MUST be inside the intended directory
    const dirWithSep = baseDir.endsWith(sep) ? baseDir : baseDir + sep
    expect(fullPath.startsWith(dirWithSep)).toBe(true)
  })

  it('sanitizes other dangerous characters', () => {
    const maliciousName = 'server:name*with?chars'
    const filename = cacheFilename(maliciousName, 80, '1.0', '1.0')
    expect(filename).toBe('server_name_with_chars-80-1.0-1.0.tools.json')
  })

  it('sanitizes version strings too', () => {
    const filename = cacheFilename('server', 80, '1.0/../2.0', 'v1.0')
    expect(filename).toBe('server-80-1.0____2.0-v1.0.tools.json')
  })

  const BASE_DIR_SECURITY = normalize('/home/user/.config/mcp/cache')

  function isSafe(filename: string): boolean {
    const fullPath = join(BASE_DIR_SECURITY, filename)
    const normalized = normalize(fullPath)
    const dirWithSep = BASE_DIR_SECURITY.endsWith(sep) ? BASE_DIR_SECURITY : BASE_DIR_SECURITY + sep
    return normalized.startsWith(dirWithSep)
  }

  it('handles basic traversal attempts (robust)', () => {
    const filename = cacheFilename('../../etc/passwd', 80, '1.0', '1.0')
    expect(filename).not.toContain('/')
    expect(filename).not.toContain('\\')
    expect(isSafe(filename)).toBe(true)
  })

  it('handles absolute paths', () => {
    const filename = cacheFilename('/etc/passwd', 80, '1.0', '1.0')
    expect(filename.startsWith('/')).toBe(false)
    expect(isSafe(filename)).toBe(true)
  })

  it('handles null bytes', () => {
    const filename = cacheFilename('server\0.json', 80, '1.0', '1.0')
    expect(filename).not.toContain('\0')
    expect(filename).toBe('server_.json-80-1.0-1.0.tools.json')
  })

  it('ensures ".." sequences are neutered', () => {
    const filename = cacheFilename('..', 80, '..', '..')
    expect(filename).not.toContain('..')
  })

  it('handles Windows style paths', () => {
    const filename = cacheFilename('C:\\Windows\\System32\\config', 80, '1.0', '1.0')
    expect(filename).not.toContain('\\')
    expect(filename).not.toContain(':')
    expect(isSafe(filename)).toBe(true)
  })
})
