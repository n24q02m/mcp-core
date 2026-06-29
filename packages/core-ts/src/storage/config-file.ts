import { existsSync } from 'node:fs'
import { mkdir, readFile, unlink, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import envPaths from 'env-paths'
import {
  decryptData,
  deriveFileKey,
  derivePassphraseKey,
  encryptData,
  LEGACY_EXPORT_SALT,
  LEGACY_PBKDF2_ITERATIONS,
  LEGACY_SALT,
  PBKDF2_ITERATIONS
} from './encryption.js'
import { getMachineId, getUsername } from './machine-id.js'

const paths = envPaths('mcp', { suffix: '' })
const DEFAULT_CONFIG_PATH = join(paths.config, 'config.enc')
const SALT_SIZE = 16

export interface ConfigStore {
  version: 1
  servers: Record<string, Record<string, string>>
}

function validateAuth(config: Record<string, unknown>): boolean {
  return Object.values(config).every((value) => typeof value === 'string')
}

function validateServer(server: unknown): boolean {
  if (!server || typeof server !== 'object' || Array.isArray(server)) return false
  return validateAuth(server as Record<string, unknown>)
}

export function validateSchema(data: unknown): data is ConfigStore {
  if (!data || typeof data !== 'object') return false
  const d = data as Record<string, unknown>
  if (d.version !== 1) return false
  if (!d.servers || typeof d.servers !== 'object' || Array.isArray(d.servers)) return false

  const servers = d.servers as Record<string, unknown>
  for (const serverName in servers) {
    if (typeof serverName !== 'string' || !validateServer(servers[serverName])) {
      return false
    }
  }

  return true
}

// Allow overriding config path for testing
let configPathOverride: string | null = null

export function setConfigPath(path: string | null): void {
  configPathOverride = path
}

function getConfigPath(): string {
  return configPathOverride ?? DEFAULT_CONFIG_PATH
}

const MAX_RETRIES = 3
const BASE_DELAY_MS = 100

async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      return await fn()
    } catch (err: unknown) {
      const isLocked = err instanceof Error && 'code' in err && (err as NodeJS.ErrnoException).code === 'EBUSY'
      if (!isLocked || attempt === MAX_RETRIES - 1) throw err
      await new Promise((r) => setTimeout(r, BASE_DELAY_MS * 2 ** attempt))
    }
  }
  throw new Error('Unreachable')
}

// Cache the derived file key to avoid expensive PBKDF2 iterations on every config read/write.
// This significantly speeds up successive configuration accesses within the same process.
let cachedKey: CryptoKey | null = null
let cachedSalt: Uint8Array | null = null

export function clearKeyCacheForTesting(): void {
  cachedKey = null
  cachedSalt = null
}

async function getKey(salt: Uint8Array): Promise<CryptoKey> {
  if (cachedKey && cachedSalt && Buffer.from(cachedSalt).equals(salt)) return cachedKey
  const [machineId, username] = await Promise.all([getMachineId(), getUsername()])
  cachedKey = await deriveFileKey(machineId, username, salt)
  cachedSalt = new Uint8Array(salt)
  return cachedKey
}

async function loadStore(): Promise<ConfigStore> {
  const configPath = getConfigPath()
  if (!existsSync(configPath)) {
    return { version: 1, servers: {} }
  }

  const [machineId, username] = await Promise.all([getMachineId(), getUsername()])
  const data = await readFile(configPath)

  // Try new format: [16-byte salt][iv][ciphertext]
  if (data.length >= SALT_SIZE + 12) {
    const salt = data.subarray(0, SALT_SIZE)
    const payload = data.subarray(SALT_SIZE)
    try {
      const key = await getKey(salt)
      const json = await decryptData(key, payload)
      const store = JSON.parse(json)
      if (!validateSchema(store)) {
        throw new Error('Invalid config schema')
      }
      return store
    } catch (_err) {
      // Fall through to legacy check
    }
  }

  // Try legacy format: [iv][ciphertext] using LEGACY_SALT
  try {
    const legacyKey = await deriveFileKey(machineId, username, LEGACY_SALT, PBKDF2_ITERATIONS)
    const json = await decryptData(legacyKey, data)
    const store = JSON.parse(json)
    if (!validateSchema(store)) {
      throw new Error('Invalid config schema')
    }
    // Auto-migrate to current iterations AND new salted format
    await saveStore(store)
    return store
  } catch (err) {
    try {
      const legacyKey = await deriveFileKey(machineId, username, LEGACY_SALT, LEGACY_PBKDF2_ITERATIONS)
      const json = await decryptData(legacyKey, data)
      const store = JSON.parse(json)
      if (!validateSchema(store)) {
        throw new Error('Invalid config schema')
      }
      // Auto-migrate
      await saveStore(store)
      return store
    } catch {
      throw err
    }
  }
}

async function saveStore(store: ConfigStore): Promise<void> {
  const configPath = getConfigPath()
  const dir = dirname(configPath)
  if (!existsSync(dir)) {
    await mkdir(dir, { recursive: true, mode: 0o700 })
  }

  let salt = cachedSalt
  if (!salt) {
    salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE))
  }

  const key = await getKey(salt)
  const encrypted = await encryptData(key, JSON.stringify(store))
  const finalData = Buffer.concat([Buffer.from(salt), encrypted])
  await withRetry(() => writeFile(configPath, finalData, { mode: 0o600 }))
}

/**
 * Schedule a process exit so an MCP client can respawn the server and pick up
 * fresh credentials from disk. Only relevant for stdio-mode servers whose
 * client supervises restart. HTTP-mode servers update credentials in-process
 * and MUST NOT call this — an exit mid-OAuth-device-code flow kills the user's
 * verification window. Skipped under vitest (NODE_ENV=test) and when
 * MCP_NO_RELOAD is set.
 */
export function scheduleReloadExit(): void {
  if (process.env.NODE_ENV !== 'test' && !process.env.MCP_NO_RELOAD) {
    setTimeout(() => process.exit(0), 1000).unref()
  }
}

export async function readConfig(serverName: string): Promise<Record<string, string> | null> {
  const store = await loadStore()
  return store.servers[serverName] ?? null
}

export async function writeConfig(serverName: string, config: Record<string, string>): Promise<void> {
  const store = await loadStore()
  store.servers[serverName] = config
  await saveStore(store)
}

export async function deleteConfig(serverName: string): Promise<void> {
  const store = await loadStore()
  delete store.servers[serverName]

  const configPath = getConfigPath()
  if (Object.keys(store.servers).length === 0) {
    if (existsSync(configPath)) {
      await unlink(configPath)
    }
  } else {
    await saveStore(store)
  }
}

/**
 * Metadata flag set by `markSetupComplete` after a successful relay-form
 * submission (POST /authorize). `runHttpServer`/`isSchemaComplete` read this
 * to distinguish "user has submitted the form" from "config.enc has values
 * written by a peer-share or partial bootstrap path". Lives alongside the
 * user's normal credential keys in the same per-server config dict.
 */
export const SETUP_COMPLETE_KEY = '_setup_complete'

/**
 * Set the `_setup_complete` flag in `serverName`'s config. Idempotent.
 * Creates a new entry with just the flag if no prior config exists (useful
 * for all-optional schemas where the user may submit an empty form).
 *
 * Strict equality semantics in `isSchemaComplete` rely on this writing the
 * literal string `"true"`.
 */
export async function markSetupComplete(serverName: string): Promise<void> {
  const existing = (await readConfig(serverName)) ?? {}
  existing[SETUP_COMPLETE_KEY] = 'true'
  await writeConfig(serverName, existing)
}

export async function listConfigs(): Promise<string[]> {
  const store = await loadStore()
  return Object.keys(store.servers)
}

export async function exportConfig(passphrase: string): Promise<Buffer> {
  const store = await loadStore()
  const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE))
  const key = await derivePassphraseKey(passphrase, salt)
  const encrypted = await encryptData(key, JSON.stringify(store))
  return Buffer.concat([Buffer.from(salt), encrypted])
}

export async function importConfig(passphrase: string, data: Buffer): Promise<void> {
  let json: string | undefined
  // Try new format: [16-byte salt][iv][ciphertext]
  if (data.length >= SALT_SIZE + 12) {
    const salt = data.subarray(0, SALT_SIZE)
    const payload = data.subarray(SALT_SIZE)
    try {
      const key = await derivePassphraseKey(passphrase, salt, PBKDF2_ITERATIONS)
      json = await decryptData(key, payload)
    } catch (_err) {
      try {
        const legacyKey = await derivePassphraseKey(passphrase, salt, LEGACY_PBKDF2_ITERATIONS)
        json = await decryptData(legacyKey, payload)
      } catch {
        // Fall through to legacy format check
      }
    }
  }

  if (!json) {
    // Try legacy format: [iv][ciphertext] using LEGACY_EXPORT_SALT
    try {
      const key = await derivePassphraseKey(passphrase, LEGACY_EXPORT_SALT, PBKDF2_ITERATIONS)
      json = await decryptData(key, data)
    } catch (err) {
      try {
        const legacyKey = await derivePassphraseKey(passphrase, LEGACY_EXPORT_SALT, LEGACY_PBKDF2_ITERATIONS)
        json = await decryptData(legacyKey, data)
      } catch {
        throw err
      }
    }
  }

  const imported = JSON.parse(json)
  if (!validateSchema(imported)) {
    throw new Error('Invalid config schema in imported data')
  }

  const store = await loadStore()
  // Merge imported servers into local config
  for (const [name, config] of Object.entries(imported.servers)) {
    store.servers[name] = config
  }
  await saveStore(store)
}
