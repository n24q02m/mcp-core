import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { credPath, PerPluginStore, setHomeDirForTesting } from '../../src/storage/per-plugin-store.js'

describe('PerPluginStore', () => {
  let testHome: string

  beforeEach(() => {
    testHome = mkdtempSync(join(tmpdir(), 'pps-test-'))
    setHomeDirForTesting(testHome)
  })

  afterEach(() => {
    setHomeDirForTesting(null)
    delete process.env.CREDENTIAL_SECRET
    rmSync(testHome, { recursive: true, force: true })
  })

  it('save and load stdio mode', async () => {
    const store = new PerPluginStore('test-plugin')
    await store.save({ GEMINI_API_KEY: 'sk-fake' })
    expect(await store.load()).toEqual({ GEMINI_API_KEY: 'sk-fake' })
  })

  it('save and load multi-user', async () => {
    process.env.CREDENTIAL_SECRET = 'test-master'
    const a = new PerPluginStore('test-plugin', 'sub-a')
    const b = new PerPluginStore('test-plugin', 'sub-b')
    await a.save({ k: 'va' })
    await b.save({ k: 'vb' })
    expect(await a.load()).toEqual({ k: 'va' })
    expect(await b.load()).toEqual({ k: 'vb' })
  })

  it('path layout', () => {
    expect(credPath('foo', null)).toContain(join('.foo-mcp', 'config.json'))
    expect(credPath('foo', 'abc-123')).toContain(join('.foo-mcp', 'subs', 'abc-123', 'config.json'))
  })

  it('path traversal protection', () => {
    expect(() => credPath('../evil', null)).toThrow(/Invalid pluginName/)
    expect(() => credPath('plugin', '../../evil')).toThrow(/Invalid sub/)
    expect(() => credPath('', null)).toThrow(/Invalid pluginName/)
    expect(() => credPath('plugin', '')).toThrow(/Invalid sub/)
  })

  it('clear', async () => {
    const store = new PerPluginStore('test-plugin')
    await store.save({ x: 1 })
    await store.clear()
    expect(await store.load()).toBeNull()
  })

  it('cross-sub isolation', async () => {
    process.env.CREDENTIAL_SECRET = 'test-master'
    const a = new PerPluginStore('plugin', 'sub-a')
    await a.save({ secret: 'for-a' })
    const b = new PerPluginStore('plugin', 'sub-b')
    expect(await b.load()).toBeNull()
  })

  it('multi-user requires CREDENTIAL_SECRET', async () => {
    delete process.env.CREDENTIAL_SECRET
    const store = new PerPluginStore('plugin', 'some-sub')
    await expect(store.save({ k: 'v' })).rejects.toThrow(/CREDENTIAL_SECRET/)
  })

  it('load returns null on tampered ciphertext', async () => {
    const store = new PerPluginStore('test-plugin')
    await store.save({ key: 'value' })
    const { readFileSync, writeFileSync } = await import('node:fs')
    const blob = readFileSync(store.credPath)
    const tampered = Buffer.from(blob)
    tampered[tampered.length - 1] ^= 0xff // flip last byte
    writeFileSync(store.credPath, tampered)
    expect(await store.load()).toBeNull()
  })
})
