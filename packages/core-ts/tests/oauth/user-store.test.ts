import { randomBytes } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { SqliteUserStore } from '../../src/oauth/user-store.js'

describe('SqliteUserStore', () => {
  let tempDir: string
  let dbPath: string
  const masterKey = randomBytes(32)

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'mcp-test-user-store-'))
    dbPath = join(tempDir, 'test.db')
  })

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true })
  })

  it('throws error if masterKey is not 32 bytes', () => {
    const invalidKey = randomBytes(31)
    expect(() => new SqliteUserStore(':memory:', invalidKey)).toThrow('masterKey must be 32 bytes')
  })

  it('saves and retrieves credentials', () => {
    const store = new SqliteUserStore(':memory:', masterKey)
    const userId = 'user123'
    const config = { api_key: 'secret-key', endpoint: 'https://api.example.com' }

    store.saveCredentials(userId, config)
    const retrieved = store.getCredentials(userId)

    expect(retrieved).toEqual(config)
    store.close()
  })

  it('updates existing credentials', () => {
    const store = new SqliteUserStore(':memory:', masterKey)
    const userId = 'user123'
    const config1 = { api_key: 'key-1' }
    const config2 = { api_key: 'key-2' }

    store.saveCredentials(userId, config1)
    store.saveCredentials(userId, config2)
    const retrieved = store.getCredentials(userId)

    expect(retrieved).toEqual(config2)
    store.close()
  })

  it('returns null for non-existent user', () => {
    const store = new SqliteUserStore(':memory:', masterKey)
    expect(store.getCredentials('no-such-user')).toBeNull()
    store.close()
  })

  it('deletes credentials', () => {
    const store = new SqliteUserStore(':memory:', masterKey)
    const userId = 'user-to-delete'
    store.saveCredentials(userId, { foo: 'bar' })
    expect(store.getCredentials(userId)).not.toBeNull()

    store.deleteCredentials(userId)
    expect(store.getCredentials(userId)).toBeNull()
    store.close()
  })

  it('stores data encrypted in the database', () => {
    // We use a file-based DB here to easily inspect it via better-sqlite3 directly
    const store = new SqliteUserStore(dbPath, masterKey)
    const userId = 'user-enc'
    const config = { secret: 'highly-sensitive-info' }
    store.saveCredentials(userId, config)
    store.close()

    // Open DB directly to check contents
    const rawDb = new Database(dbPath)
    const row = rawDb.prepare('SELECT encrypted_config FROM users WHERE user_id = ?').get(userId) as {
      encrypted_config: Buffer
    }
    rawDb.close()

    expect(row).toBeDefined()
    expect(row.encrypted_config).toBeInstanceOf(Buffer)

    // The raw bytes should NOT contain the plaintext string
    const rawString = row.encrypted_config.toString('utf-8')
    expect(rawString).not.toContain('highly-sensitive-info')
    expect(rawString).not.toContain('secret')
  })

  it('returns null on decryption failure (e.g. tampered data)', () => {
    const store = new SqliteUserStore(dbPath, masterKey)
    const userId = 'tamper-me'
    store.saveCredentials(userId, { key: 'val' })
    store.close()

    // Tamper with the encrypted BLOB
    const rawDb = new Database(dbPath)
    const row = rawDb.prepare('SELECT encrypted_config FROM users WHERE user_id = ?').get(userId) as {
      encrypted_config: Buffer
    }
    const tampered = Buffer.from(row.encrypted_config)
    // Flip some bits in the ciphertext area (after 12 IV + 16 tag)
    tampered[30] = tampered[30] ^ 0xff
    rawDb.prepare('UPDATE users SET encrypted_config = ? WHERE user_id = ?').run(tampered, userId)
    rawDb.close()

    const store2 = new SqliteUserStore(dbPath, masterKey)
    expect(store2.getCredentials(userId)).toBeNull()
    store2.close()
  })

  it('can use :memory: database', () => {
    const store = new SqliteUserStore(':memory:', masterKey)
    store.saveCredentials('mem', { ok: 'true' })
    expect(store.getCredentials('mem')).toEqual({ ok: 'true' })
    store.close()
  })
})
