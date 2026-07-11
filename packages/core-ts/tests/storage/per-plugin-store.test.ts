import { createCipheriv, randomBytes, scryptSync } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { InMemoryBackend } from '../../src/storage/backends.js'
import { credPath, PerPluginStore, setHomeDirForTesting } from '../../src/storage/per-plugin-store.js'

// Mocking node:fs/promises for the atomic-write rename-failure case (Task 5,
// mirrors the mock in backends.test.ts from Task 4). Only `rename` is
// intercepted, gated on the destination path so unrelated writes in this
// file keep using the real filesystem. The gate substring is unique to this
// file's plugin name to avoid colliding with backends.test.ts's own trigger.
vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  return {
    ...actual,
    rename: vi.fn((oldPath, newPath) => {
      if (typeof newPath === 'string' && newPath.includes('atomic-key-fail-trigger')) {
        return Promise.reject(new Error('simulated rename failure'))
      }
      return actual.rename(oldPath, newPath)
    })
  }
})

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
    // "." is allowed (version-style segments), so a bare ".." with no "/" is caught
    // only by the explicit dotdot guard. The validation regex must NOT be global:
    // a /g flag makes .test() stateful and could bypass the second check.
    expect(() => credPath('plugin', 'a..b')).toThrow(/Invalid sub/)
    expect(() => credPath('plug..in', null)).toThrow(/Invalid pluginName/)
  })

  it('accepts token_urlsafe subs (underscore + hyphen)', () => {
    // The OAuth AS mints sub = token_urlsafe(16); its base64url alphabet includes
    // "_" and "-". Both must be accepted, else ~half of all per-sub credential saves
    // fail with "Invalid sub" (regression: telegram CF, 2026-06-17).
    const sub = 'oG5FyoFE-RWqI_aciDl4zA'
    expect(credPath('better-telegram', sub)).toContain(join('subs', sub, 'config.json'))
    // "/" stays rejected so path traversal protection is unaffected.
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

  it('load returns null on short blob', async () => {
    const backend = new InMemoryBackend()
    const store = new PerPluginStore('test-plugin', null, backend)
    await backend.put('test-plugin/config', Buffer.allocUnsafe(28))
    expect(await store.load()).toBeNull()
  })

  it('load returns null on invalid JSON', async () => {
    const backend = new InMemoryBackend()
    const pluginName = 'test-plugin'
    const sub = 'test-sub'
    const secret = 'test-secret'
    process.env.CREDENTIAL_SECRET = secret

    const store = new PerPluginStore(pluginName, sub, backend)

    // Manually derive key using scrypt parameters from source
    const key = scryptSync(secret, Buffer.from(`${pluginName}:${sub}`, 'utf-8'), 32, {
      N: 16384,
      r: 8,
      p: 1
    })

    // Encrypt non-JSON string
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 })
    const plaintext = Buffer.from('not-json', 'utf-8')
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    const tag = cipher.getAuthTag()

    await backend.put(`${pluginName}/subs/${sub}/config`, Buffer.concat([iv, ciphertext, tag]))

    expect(await store.load()).toBeNull()
  })

  it('machine key write is atomic (no torn .secret on rename failure)', async () => {
    // Mirrors Task 4's LocalFsBackend rename-failure test, but for the
    // machine-key path: a crash mid-write must not leave a half-written
    // .secret on disk (that would silently decrypt to garbage on next read).
    const pluginName = 'atomic-key-fail-trigger'
    const store = new PerPluginStore(pluginName)

    await expect(store.save({ k: 'v' })).rejects.toThrow('simulated rename failure')

    const secretDir = join(testHome, `.${pluginName}-mcp`)
    expect(existsSync(join(secretDir, '.secret'))).toBe(false)
    expect(readdirSync(secretDir).some((entry) => entry.endsWith('.tmp'))).toBe(false)
  })

  it('load stays silent when no blob exists', async () => {
    const store = new PerPluginStore('test-plugin')
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(await store.load()).toBeNull()
    expect(errorSpy).not.toHaveBeenCalled()
    errorSpy.mockRestore()
  })

  it('load logs the cred key on a truncated blob', async () => {
    const backend = new InMemoryBackend()
    const store = new PerPluginStore('test-plugin', null, backend)
    await backend.put('test-plugin/config', Buffer.allocUnsafe(28))

    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(await store.load()).toBeNull()
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('test-plugin/config'))
    errorSpy.mockRestore()
  })

  it('load logs the cred key on a corrupt/tampered blob', async () => {
    const store = new PerPluginStore('test-plugin')
    await store.save({ key: 'value' })
    const { readFileSync, writeFileSync } = await import('node:fs')
    const blob = readFileSync(store.credPath)
    const tampered = Buffer.from(blob)
    tampered[tampered.length - 1] ^= 0xff // flip last byte
    writeFileSync(store.credPath, tampered)

    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(await store.load()).toBeNull()
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('test-plugin/config'))
    errorSpy.mockRestore()
  })
})
