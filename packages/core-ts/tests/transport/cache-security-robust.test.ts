import { join, normalize, sep } from 'node:path'
import { describe, expect, it } from 'vitest'
import { cacheFilename } from '../../src/transport/cache.js'

describe('cache path traversal robust', () => {
  const BASE_DIR = normalize('/home/user/.config/mcp/cache')

  function isSafe(filename: string): boolean {
    const fullPath = join(BASE_DIR, filename)
    const normalized = normalize(fullPath)
    // On Linux normalize preserves leading .. if they go above root,
    // but here BASE_DIR is absolute.
    // If filename is "../../etc/passwd", fullPath is "/home/user/.config/mcp/cache/../../etc/passwd"
    // normalized is "/home/user/.config/etc/passwd"
    // which does NOT start with BASE_DIR + sep
    const dirWithSep = BASE_DIR.endsWith(sep) ? BASE_DIR : BASE_DIR + sep
    return normalized.startsWith(dirWithSep)
  }

  it('handles basic traversal attempts', () => {
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
    // We expect ".." to be replaced by something safer, like "__"
    expect(filename).not.toContain('..')
  })

  it('handles Windows style paths', () => {
    const filename = cacheFilename('C:\\Windows\\System32\\config', 80, '1.0', '1.0')
    expect(filename).not.toContain('\\')
    expect(filename).not.toContain(':')
    expect(isSafe(filename)).toBe(true)
  })
})
