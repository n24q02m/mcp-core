/**
 * Pluggable credential backends.
 *
 * A backend stores and retrieves OPAQUE ciphertext blobs keyed by a string.
 * Encryption and key derivation live in PerPluginStore; backends never see
 * plaintext. This seam lets MCP servers run serverless (e.g. Cloudflare Workers
 * KV) while stdio/VM deployments keep the on-disk layout via LocalFsBackend.
 */

import { mkdir, readFile, unlink, writeFile } from 'node:fs/promises'
import { dirname, join, resolve, sep } from 'node:path'
import { getHomeDir } from './home-dir.js'

/** Stores opaque ciphertext blobs keyed by a string. */
export interface CredentialBackend {
  get(key: string): Promise<Buffer | null>
  put(key: string, blob: Buffer): Promise<void>
  delete(key: string): Promise<void>
}

/** Map-backed backend, primarily for tests. */
export class InMemoryBackend implements CredentialBackend {
  private store = new Map<string, Buffer>()

  async get(key: string): Promise<Buffer | null> {
    return this.store.get(key) ?? null
  }

  async put(key: string, blob: Buffer): Promise<void> {
    this.store.set(key, blob)
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key)
  }
}

function validateComponent(name: string): string {
  if (!name || name === '.' || name === '..' || name.includes('/') || name.includes('\\') || name.includes('\x00')) {
    throw new Error(`Invalid path component: ${name}`)
  }
  return name
}

/**
 * Map a backend key to its on-disk path.
 *
 *   "<plugin>/config"            -> ~/.<plugin>-mcp/config.json
 *   "<plugin>/subs/<sub>/config" -> ~/.<plugin>-mcp/subs/<sub>/config.json
 */
function keyToPath(key: string): string {
  const slash = key.indexOf('/')
  const plugin = slash === -1 ? key : key.slice(0, slash)
  const rest = slash === -1 ? '' : key.slice(slash + 1)
  validateComponent(plugin)

  const base = join(getHomeDir(), `.${plugin}-mcp`)
  let path: string
  if (rest === 'config') {
    path = join(base, 'config.json')
  } else if (rest.startsWith('subs/') && rest.endsWith('/config')) {
    const sub = rest.slice('subs/'.length, -'/config'.length)
    validateComponent(sub)
    path = join(base, 'subs', sub, 'config.json')
  } else {
    throw new Error(`Invalid backend key: ${key}`)
  }

  // Defense-in-depth: validateComponent already rejects separators/./../empty/NUL.
  const baseResolved = resolve(base)
  const pathResolved = resolve(path)
  if (pathResolved !== baseResolved && !pathResolved.startsWith(baseResolved + sep)) {
    throw new Error(`Path escapes base: ${key}`)
  }
  return path
}

/** Stores blobs on local disk, preserving the per-plugin layout. */
export class LocalFsBackend implements CredentialBackend {
  async get(key: string): Promise<Buffer | null> {
    const path = keyToPath(key)
    try {
      return await readFile(path)
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null
      throw err
    }
  }

  async put(key: string, blob: Buffer): Promise<void> {
    const path = keyToPath(key)
    await mkdir(dirname(path), { recursive: true, mode: 0o700 })
    await writeFile(path, blob, { mode: 0o600 })
  }

  async delete(key: string): Promise<void> {
    const path = keyToPath(key)
    try {
      await unlink(path)
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err
    }
  }
}

/** Minimal injectable HTTP client returning status + body. */
export interface Http {
  request(
    method: string,
    url: string,
    data?: Buffer,
    headers?: Record<string, string>
  ): Promise<{ status: number; body: Buffer }>
}

/**
 * Default HTTP implementation over global fetch.
 *
 * fetch resolves on 4xx/5xx and rejects only on network error, so status checks
 * in CfKvBackend handle HTTP errors while transport errors propagate -- matching
 * the Python httpx client behavior.
 */
const fetchHttp: Http = {
  async request(method, url, data, headers) {
    const resp = await fetch(url, {
      method,
      body: data ? new Uint8Array(data) : undefined,
      headers
    })
    const body = Buffer.from(await resp.arrayBuffer())
    return { status: resp.status, body }
  }
}

/**
 * Stores blobs in a Cloudflare Workers KV namespace over HTTP.
 *
 * Error contract: 200 -> data, 404 -> absent (null for get, no-op for delete).
 * Every other HTTP status, plus transport errors from the HTTP client, raises --
 * failures are loud, never silently returned as data. Error messages carry the
 * status only; never the token or the response body.
 */
export class CfKvBackend implements CredentialBackend {
  private readonly baseUrl: string
  private readonly token?: string
  private readonly http: Http

  constructor(baseUrl: string, token?: string, http: Http = fetchHttp) {
    this.baseUrl = baseUrl.replace(/\/+$/, '')
    this.token = token
    this.http = http
  }

  private url(key: string): string {
    return `${this.baseUrl}/${encodeURIComponent(key)}`
  }

  private headers(): Record<string, string> {
    return this.token ? { Authorization: `Bearer ${this.token}` } : {}
  }

  async get(key: string): Promise<Buffer | null> {
    const { status, body } = await this.http.request('GET', this.url(key), undefined, this.headers())
    if (status === 200) return body
    if (status === 404) return null
    throw new Error(`CfKvBackend get failed: HTTP ${status}`)
  }

  async put(key: string, blob: Buffer): Promise<void> {
    const { status } = await this.http.request('PUT', this.url(key), blob, this.headers())
    if (status !== 200 && status !== 204) {
      throw new Error(`CfKvBackend put failed: HTTP ${status}`)
    }
  }

  async delete(key: string): Promise<void> {
    const { status } = await this.http.request('DELETE', this.url(key), undefined, this.headers())
    if (status !== 200 && status !== 204 && status !== 404) {
      throw new Error(`CfKvBackend delete failed: HTTP ${status}`)
    }
  }
}

/** Select a credential backend from the MCP_STORAGE_BACKEND env var. */
export function backendFromEnv(): CredentialBackend {
  const kind = (process.env.MCP_STORAGE_BACKEND ?? 'local').toLowerCase()
  if (kind === 'local' || kind === 'local-fs' || kind === '') {
    return new LocalFsBackend()
  }
  if (kind === 'cf-kv') {
    const baseUrl = process.env.MCP_KV_BASE_URL
    if (!baseUrl) throw new Error('MCP_KV_BASE_URL is required when MCP_STORAGE_BACKEND=cf-kv')
    return new CfKvBackend(baseUrl, process.env.MCP_KV_TOKEN)
  }
  throw new Error(`Unknown MCP_STORAGE_BACKEND: ${kind}`)
}
