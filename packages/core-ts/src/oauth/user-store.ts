/**
 * Per-user encrypted credential store for MCP HTTP modes.
 * Uses better-sqlite3 for persistence and Node.js crypto for AES-256-GCM at-rest encryption.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import Database from 'better-sqlite3'

export interface IUserCredentialStore {
  saveCredentials(userId: string, config: Record<string, string>): void
  getCredentials(userId: string): Record<string, string> | null
  deleteCredentials(userId: string): void
}

export class SqliteUserStore implements IUserCredentialStore {
  private db: Database.Database
  private masterKey: Buffer

  /**
   * @param dbPath Path to the SQLite DB file.
   * @param masterKey 32-byte AES key for at-rest encryption.
   */
  constructor(dbPath: string, masterKey: Buffer) {
    if (masterKey.length !== 32) throw new Error('masterKey must be 32 bytes')
    this.masterKey = masterKey

    // Ensure directory exists with strict permissions (owner-only access).
    // 0o700 = owner read+write+exec only; group/other denied. This is the
    // secure default for a credential store directory.
    mkdirSync(dirname(dbPath), { recursive: true, mode: 0o700 })

    this.db = new Database(dbPath)
    this.db.pragma('journal_mode = WAL')
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        encrypted_config BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `)
  }

  private encrypt(plaintext: string): Buffer {
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', this.masterKey, iv, { authTagLength: 16 })
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()])
    const tag = cipher.getAuthTag()
    // Layout: [12 iv] [16 tag] [... ciphertext]
    return Buffer.concat([iv, tag, encrypted])
  }

  private decrypt(payload: Buffer): string {
    const iv = payload.subarray(0, 12)
    const tag = payload.subarray(12, 28)
    const ciphertext = payload.subarray(28)
    const decipher = createDecipheriv('aes-256-gcm', this.masterKey, iv, { authTagLength: 16 })
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf-8')
  }

  saveCredentials(userId: string, config: Record<string, string>): void {
    const now = Math.floor(Date.now() / 1000)
    const encrypted = this.encrypt(JSON.stringify(config))

    this.db
      .prepare(`
        INSERT INTO users (user_id, encrypted_config, created_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          encrypted_config = excluded.encrypted_config,
          updated_at = excluded.updated_at
      `)
      .run(userId, encrypted, now, now)
  }

  getCredentials(userId: string): Record<string, string> | null {
    const row = this.db.prepare('SELECT encrypted_config FROM users WHERE user_id = ?').get(userId) as
      | { encrypted_config: Buffer }
      | undefined

    if (!row) return null

    try {
      return JSON.parse(this.decrypt(Buffer.from(row.encrypted_config)))
    } catch {
      return null
    }
  }

  deleteCredentials(userId: string): void {
    this.db.prepare('DELETE FROM users WHERE user_id = ?').run(userId)
  }

  close(): void {
    this.db.close()
  }
}
