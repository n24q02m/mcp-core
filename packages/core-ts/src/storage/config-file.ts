import { existsSync } from 'node:fs'
import { mkdir, readFile, unlink, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import envPaths from 'env-paths'
import {
  decryptData,
  deriveFileKey,
  derivePassphraseKey,
  encryptData,
  LEGACY_PBKDF2_ITERATIONS,
  PBKDF2_ITERATIONS
} from './encryption.js'
import { getMachineId, getUsername } from './machine-id.js'

const paths = envPaths('mcp', { suffix: '' })
const DEFAULT_CONFIG_PATH = join(paths.config, 'config.enc')

interface ConfigStore {
  version: 1
  servers: Record<string, Record<string, string>>
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

export function clearKeyCacheForTesting(): void {
  cachedKey = null
}

async function getKey(): Promise<CryptoKey> {
  if (cachedKey) return cachedKey
  const [machineId, username] = await Promise.all([getMachineId(), getUsername()])
  cachedKey = await deriveFileKey(machineId, username)
  return cachedKey
}

async function loadStore(): Promise<ConfigStore> {
  const configPath = getConfigPath()
  if (!existsSync(configPath)) {
    return { version: 1, servers: {} }
  }

  const [machineId, username] = await Promise.all([getMachineId(), getUsername()])
  const data = await readFile(configPath)

  try {
    const key = await getKey()
    const json = await decryptData(key, data)
    return JSON.parse(json) as ConfigStore
  } catch (err) {
    try {
      const legacyKey = await deriveFileKey(machineId, username, LEGACY_PBKDF2_ITERATIONS)
      const json = await decryptData(legacyKey, data)
      const store = JSON.parse(json) as ConfigStore
      // Auto-migrate to current iterations
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
    await mkdir(dir, { recursive: true })
  }
  const key = await getKey()
  const encrypted = await encryptData(key, JSON.stringify(store))
  await withRetry(() => writeFile(configPath, encrypted))
}

function scheduleRestart() {
  if (process.env.NODE_ENV !== 'test' && !process.env.MCP_NO_RELOAD) {
    // Schedule process exit to reload config via MCP client
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
  scheduleRestart()
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
  scheduleRestart()
}

export async function listConfigs(): Promise<string[]> {
  const store = await loadStore()
  return Object.keys(store.servers)
}

export async function exportConfig(passphrase: string): Promise<Buffer> {
  const store = await loadStore()
  const key = await derivePassphraseKey(passphrase)
  return encryptData(key, JSON.stringify(store))
}

export async function importConfig(passphrase: string, data: Buffer): Promise<void> {
  let json: string
  try {
    const key = await derivePassphraseKey(passphrase, PBKDF2_ITERATIONS)
    json = await decryptData(key, data)
  } catch (err) {
    try {
      const legacyKey = await derivePassphraseKey(passphrase, LEGACY_PBKDF2_ITERATIONS)
      json = await decryptData(legacyKey, data)
    } catch {
      throw err
    }
  }
  const imported = JSON.parse(json) as ConfigStore

  const store = await loadStore()
  // Merge imported servers into local config
  for (const [name, config] of Object.entries(imported.servers)) {
    store.servers[name] = config
  }
  await saveStore(store)
  scheduleRestart()
}
