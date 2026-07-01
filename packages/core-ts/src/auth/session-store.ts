/**
 * Durable, TTL-bounded store for short-lived OAuth handshake state
 * (delegated-flow ``pendingSessions`` + issued ``authCodes``).
 *
 * The delegated OAuth round-trip spans two independent HTTP requests
 * (``/authorize`` -> upstream consent -> ``/callback`` -> ``/token``). On a
 * serverless/container deploy (CF single-DO + ``sleepAfter``) the container can
 * cold-start or be a different instance between those requests, so an
 * in-process ``Map`` loses the state and ``/callback`` returns "Invalid state".
 * Backing the state with a shared durable KV survives the restart.
 *
 * A ``SessionKv`` (get/put/delete of opaque strings) is injected in deploy mode
 * (e.g. the container's ``kv.internal`` backend); when omitted the store falls
 * back to a process-local ``Map`` (stdio / single-process, where one request
 * context handles the whole flow).
 */

export interface SessionKv {
  get(key: string): Promise<string | null>
  put(key: string, value: string): Promise<void>
  delete(key: string): Promise<void>
}

/** A Buffer-based blob backend, matching mcp-core's ``CredentialBackend`` / ``CfKvBackend``. */
export interface BufferKvBackend {
  get(key: string): Promise<Buffer | null>
  put(key: string, blob: Buffer): Promise<void>
  delete(key: string): Promise<void>
}

const OAUTH_KEY_PREFIX = 'delegated-oauth:'

/**
 * Adapt a Buffer-based blob backend (e.g. ``CfKvBackend`` over the container's
 * ``kv.internal`` handler) to the string ``SessionKv`` interface. Keys are
 * namespaced so the short-lived OAuth handshake state can share a KV with the
 * server's other data (credential vaults, etc.) without colliding.
 */
export function wrapKvBackendAsSessionKv(backend: BufferKvBackend): SessionKv {
  const nsKey = (key: string): string => `${OAUTH_KEY_PREFIX}${key}`
  return {
    async get(key: string): Promise<string | null> {
      const blob = await backend.get(nsKey(key))
      return blob === null ? null : blob.toString('utf8')
    },
    async put(key: string, value: string): Promise<void> {
      await backend.put(nsKey(key), Buffer.from(value, 'utf8'))
    },
    async delete(key: string): Promise<void> {
      await backend.delete(nsKey(key))
    }
  }
}

export interface SessionStore<T> {
  get(key: string): Promise<T | undefined>
  set(key: string, value: T): Promise<void>
  delete(key: string): Promise<void>
}

interface Envelope<T> {
  value: T
  createdAt: number
}

export function createSessionStore<T>(kv: SessionKv | undefined, ttlSeconds: number): SessionStore<T> {
  const ttlMs = ttlSeconds * 1000

  // In-memory fallback (stdio / single-process): a Map behind the same async
  // SessionKv shape so the rest of the logic is backend-agnostic.
  const backend: SessionKv =
    kv ??
    (() => {
      const mem = new Map<string, string>()
      return {
        async get(key: string) {
          return mem.get(key) ?? null
        },
        async put(key: string, value: string) {
          mem.set(key, value)
        },
        async delete(key: string) {
          mem.delete(key)
        }
      }
    })()

  return {
    async get(key: string): Promise<T | undefined> {
      const raw = await backend.get(key)
      if (raw === null) return undefined
      let env: Envelope<T>
      try {
        env = JSON.parse(raw) as Envelope<T>
      } catch {
        return undefined
      }
      if (Date.now() - env.createdAt >= ttlMs) {
        // Lazy expiry: drop stale entries on read.
        await backend.delete(key)
        return undefined
      }
      return env.value
    },
    async set(key: string, value: T): Promise<void> {
      const env: Envelope<T> = { value, createdAt: Date.now() }
      await backend.put(key, JSON.stringify(env))
    },
    async delete(key: string): Promise<void> {
      await backend.delete(key)
    }
  }
}
