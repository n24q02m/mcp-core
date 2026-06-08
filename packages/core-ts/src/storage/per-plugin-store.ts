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
import { mkdir, readFile, unlink, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

// Module-level override for testing.
let homeDirOverride: string | null = null

/** Override the home directory used by this module. Pass null to reset. */
export function setHomeDirForTesting(dir: string | null): void {
  homeDirOverride = dir
}

function getHomeDir(): string {
  return homeDirOverride ?? homedir()
}

function validatePathComponent(name: string, label: string): void {
  if (!name || name.includes('/') || name.includes('\\') || name.includes('..')) {
    throw new Error(`Invalid ${label}: ${name}`)
  }
}

export function credPath(pluginName: string, sub: string | null): string {
  validatePathComponent(pluginName, 'plugin name')
  const base = join(getHomeDir(), `.${pluginName}-mcp`)
  if (sub) {
    validatePathComponent(sub, 'sub identifier')
    return join(base, 'subs', sub, 'config.json')
  }
  return join(base, 'config.json')
}

async function loadOrGenMachineKey(pluginName: string): Promise<Buffer> {
  const secretPath = join(getHomeDir(), `.${pluginName}-mcp`, '.secret')
  try {
    return await readFile(secretPath)
  } catch {
    const key = randomBytes(32)
    await mkdir(join(getHomeDir(), `.${pluginName}-mcp`), { recursive: true, mode: 0o700 })
    await writeFile(secretPath, key, { mode: 0o600 })
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

  constructor(
    public pluginName: string,
    public sub: string | null = null
  ) {
    this.credPath = credPath(pluginName, sub)
  }

  private async key(): Promise<Buffer> {
    return this.sub ? deriveMultiUserKey(this.pluginName, this.sub) : loadOrGenMachineKey(this.pluginName)
  }

  async load(): Promise<Record<string, unknown> | null> {
    let blob: Buffer
    try {
      blob = await readFile(this.credPath)
    } catch {
      return null
    }
    // Format: [12-byte IV][ciphertext][16-byte GCM tag]
    if (blob.length < 29) return null
    const iv = blob.subarray(0, 12)
    const tag = blob.subarray(blob.length - 16)
    const data = blob.subarray(12, blob.length - 16)
    const decipher = createDecipheriv('aes-256-gcm', await this.key(), iv, { authTagLength: 16 })
    decipher.setAuthTag(tag)
    try {
      const plaintext = Buffer.concat([decipher.update(data), decipher.final()])
      return JSON.parse(plaintext.toString('utf-8')) as Record<string, unknown>
    } catch {
      return null
    }
  }

  async save(payload: Record<string, unknown>): Promise<void> {
    await mkdir(dirname(this.credPath), { recursive: true, mode: 0o700 })
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', await this.key(), iv, { authTagLength: 16 })
    const plaintext = Buffer.from(JSON.stringify(payload), 'utf-8')
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    const tag = cipher.getAuthTag()
    await writeFile(this.credPath, Buffer.concat([iv, ciphertext, tag]), { mode: 0o600 })
  }

  async clear(): Promise<void> {
    try {
      await unlink(this.credPath)
    } catch {
      // ignore if file does not exist
    }
  }
}
