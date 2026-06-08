import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { credPath, setHomeDirForTesting } from '../../src/storage/per-plugin-store.js'

describe('PerPluginStore Security', () => {
  const testHome = resolve('/tmp/pps-security-test')

  it('throws on path traversal in pluginName', () => {
    setHomeDirForTesting(testHome)
    expect(() => credPath('../evil', null)).toThrow('Invalid plugin name: ../evil')
    expect(() => credPath('foo/bar', null)).toThrow('Invalid plugin name: foo/bar')
    expect(() => credPath('..\\evil', null)).toThrow('Invalid plugin name: ..\\evil')
  })

  it('throws on path traversal in sub', () => {
    setHomeDirForTesting(testHome)
    expect(() => credPath('plugin', '../../evil')).toThrow('Invalid sub identifier: ../../evil')
    expect(() => credPath('plugin', 'foo/bar')).toThrow('Invalid sub identifier: foo/bar')
    expect(() => credPath('plugin', '..\\evil')).toThrow('Invalid sub identifier: ..\\evil')
  })

  it('allows valid names', () => {
    setHomeDirForTesting(testHome)
    const path = credPath('valid-plugin_123', 'valid-sub.456')
    expect(path).toContain('.valid-plugin_123-mcp')
    expect(path).toContain('valid-sub.456')
  })
})
