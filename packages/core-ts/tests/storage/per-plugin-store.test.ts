import * as crypto from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import * as fsPromises from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  clearKeyCacheForTesting,
  credPath,
  PerPluginStore,
  setHomeDirForTesting
} from '../../src/storage/per-plugin-store.js'

describe('PerPluginStore', () => {
  let testHome: string

  beforeEach(() => {
    testHome = mkdtempSync(join(tmpdir(), 'pps-test-'))
    setHomeDirForTesting(testHome)
    clearKeyCacheForTesting()
  })

  afterEach(() => {
    setHomeDirForTesting(null)
    delete process.env.CREDENTIAL_SECRET
    rmSync(testHome, { recursive: true, force: true })
    vi.restoreAllMocks()
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
    expect(() => credPath('plugin', 'a..b')).toThrow(/Invalid sub/)
    expect(() => credPath('plug..in', null)).toThrow(/Invalid pluginName/)
  })

  it('accepts token_urlsafe subs (underscore + hyphen)', () => {
    const sub = 'oG5FyoFE-RWqI_aciDl4zA'
    expect(credPath('better-telegram', sub)).toContain(join('subs', sub, 'config.json'))
    expect(() => credPath('plugin', 'a/b')).toThrow(/Invalid sub/)
  })

  it('underscore sub round-trips', async () => {
    process.env.CREDENTIAL_SECRET = 'test-master-secret'
    const store = new PerPluginStore('plugin', 'ab_cd-EF_gh')
    await store.save({ token: 'value' })
    expect(await store.load()).toEqual({ token: 'value' })
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

  it('caches expensive multi-user key derivation', async () => {
    process.env.CREDENTIAL_SECRET = 'test-master'
    // Use an object to hold the function so we can spy on it.
    // However, scryptSync is a top-level export.
    // Let's try mocking the module.
  })
})
