/**
 * Per-plugin encrypted credential store.
 *
 * Layout:
 *   Stdio / HTTP single-user: ~/.<plugin>-mcp/config.json
 *   HTTP multi-user:          ~/.<plugin>-mcp/subs/<sub>/config.json
 *
 * Encryption:
 *   Stdio / single-user: AES-256-GCM with machine-bound key persisted at
 *     ~/.<plugin>-mcp/.secret (auto-generated, 32 bytes, 0600).
 *   HTTP multi-user:    AES-256-GCM with key derived via scrypt from env
 *     CREDENTIAL_SECRET, salt `<plugin>:<sub>`.
 *
 * Replaces deprecated config-file (shared config.enc) which caused
 * multi-daemon path-drift contention with platformdirs version skew.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto'
import { mkdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { atomicWriteFile } from './atomic-write.js'
import { backendFromEnv, type CredentialBackend } from './backends.js'
import { getHomeDir } from './home-dir.js'

export { setHomeDirForTesting } from './home-dir.js'

export function credPath(pluginName: string, sub: string | null): string {
  // Underscore is allowed because the OAuth AS mints sub = token_urlsafe(), whose
  // base64url alphabet includes "_" and "-"; rejecting "_" failed ~half of all
  // per-sub credential saves with "Invalid sub". Path traversal stays blocked by the
  // explicit ".." check below and by "/" remaining outside the class. The regex is
  // NOT global: a /g flag makes .test() stateful (lastIndex advances across the two
  // calls below), which can bypass validation on the second input.
  const unsafe = /[^a-zA-Z0-9._-]/
  if (!pluginName || unsafe.test(pluginName) || pluginName.includes('..')) {
    throw new Error('Invalid pluginName')
  }
  if (sub !== null && (!sub || unsafe.test(sub) || sub.includes('..'))) {
    throw new Error('Invalid sub')
  }
  const base = join(getHomeDir(), `.${pluginName}-mcp`)
  return sub ? join(base, 'subs', sub, 'config.json') : join(base, 'config.json')
}

async function loadOrGenMachineKey(pluginName: string): Promise<Buffer> {
  const secretPath = join(getHomeDir(), `.${pluginName}-mcp`, '.secret')
  try {
    return await readFile(secretPath)
  } catch {
    const key = randomBytes(32)
    await mkdir(join(getHomeDir(), `.${pluginName}-mcp`), { recursive: true, mode: 0o700 })
    await atomicWriteFile(secretPath, key)
    return key
  }
}

function deriveMultiUserKey(pluginName: string, sub: string): Buffer {
  const master = process.env.CREDENTIAL_SECRET
  if (!master) {
    throw new Error('CREDENTIAL_SECRET env required for HTTP multi-user mode')
  }
  return scryptSync(master, Buffer.from(`${pluginName}:${sub}`, 'utf-8'), 32, {
    N: 16384,
    r: 8,
    p: 1
  })
}

export class PerPluginStore {
  readonly credPath: string
  private readonly credKey: string
  private readonly backend: CredentialBackend

  constructor(
    public pluginName: string,
    public sub: string | null = null,
    backend?: CredentialBackend
  ) {
    this.credPath = credPath(pluginName, sub)
    this.credKey = sub ? `${pluginName}/subs/${sub}/config` : `${pluginName}/config`
    this.backend = backend ?? backendFromEnv()
  }

  private async key(): Promise<Buffer> {
    return this.sub ? deriveMultiUserKey(this.pluginName, this.sub) : loadOrGenMachineKey(this.pluginName)
  }

  async load(): Promise<Record<string, unknown> | null> {
    const blob = await this.backend.get(this.credKey)
    if (blob === null) return null
    // Format: [12-byte IV][ciphertext][16-byte GCM tag]
    if (blob.length < 29) {
      console.error(
        `[mcp-core PerPluginStore] Credential blob for ${this.credKey} is corrupt or the encryption key changed; treating as not configured (re-run setup to restore)`
      )
      return null
    }
    const iv = blob.subarray(0, 12)
    const tag = blob.subarray(blob.length - 16)
    const data = blob.subarray(12, blob.length - 16)
    const decipher = createDecipheriv('aes-256-gcm', await this.key(), iv, { authTagLength: 16 })
    decipher.setAuthTag(tag)
    try {
      const plaintext = Buffer.concat([decipher.update(data), decipher.final()])
      return JSON.parse(plaintext.toString('utf-8')) as Record<string, unknown>
    } catch {
      console.error(
        `[mcp-core PerPluginStore] Credential blob for ${this.credKey} is corrupt or the encryption key changed; treating as not configured (re-run setup to restore)`
      )
      return null
    }
  }

  async save(payload: Record<string, unknown>): Promise<void> {
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', await this.key(), iv, { authTagLength: 16 })
    const plaintext = Buffer.from(JSON.stringify(payload), 'utf-8')
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    const tag = cipher.getAuthTag()
    await this.backend.put(this.credKey, Buffer.concat([iv, ciphertext, tag]))
  }

  async clear(): Promise<void> {
    await this.backend.delete(this.credKey)
  }

  /**
   * Whether a credential blob is stored at all, regardless of whether it
   * decrypts. `load()` returns null for both "absent" and "corrupt"; a
   * built-in CLI (`config status` / `doctor`) needs to tell the two apart to
   * report "not configured" vs "corrupt (re-run setup)". Reads only the
   * opaque backend blob, never the plaintext.
   */
  async hasStoredBlob(): Promise<boolean> {
    return (await this.backend.get(this.credKey)) !== null
  }
}
