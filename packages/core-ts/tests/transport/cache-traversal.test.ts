import { join, normalize, sep } from 'node:path'
import { describe, expect, it } from 'vitest'
import { cacheFilename } from '../../src/transport/cache.js'

describe('cache path traversal', () => {
  it('sanitizes path traversal characters in filename', () => {
    const maliciousName = '../../etc/passwd'
    const filename = cacheFilename(maliciousName, 80, '1.0', '1.0')

    // It should no longer contain '/'
    expect(filename).not.toContain('/')
    expect(filename).not.toContain('\\')
    expect(filename).toBe('______etc_passwd-80-1.0-1.0.tools.json')

    const dir = normalize('/tmp/mcp-cache')
    const fullPath = normalize(join(dir, filename))

    // The resulting path MUST be inside the intended directory
    const dirWithSep = dir.endsWith(sep) ? dir : dir + sep
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
})
