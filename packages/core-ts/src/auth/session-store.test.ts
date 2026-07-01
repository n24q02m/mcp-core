import { describe, expect, it } from 'vitest'
import { createSessionStore, type SessionKv, wrapKvBackendAsSessionKv } from './session-store.js'

// In-memory SessionKv double simulating a shared DURABLE store (CF KV). The key
// property under test: two independent store instances backed by the same KV see
// each other's writes — this is exactly the cross-container-restart survival the
// notion delegated-OAuth flow needs (bootstrap /authorize and /callback can land
// on different / restarted container instances).
function makeSharedKv(): SessionKv {
  const backing = new Map<string, string>()
  return {
    async get(key) {
      return backing.get(key) ?? null
    },
    async put(key, value) {
      backing.set(key, value)
    },
    async delete(key) {
      backing.delete(key)
    }
  }
}

describe('createSessionStore', () => {
  it('persists a value across independent store instances sharing the same KV', async () => {
    const kv = makeSharedKv()
    const storeA = createSessionStore<{ nonce: string }>(kv, 600)
    await storeA.set('sess-1', { nonce: 'abc' })

    // storeB = a fresh store object (simulating a restarted container) on the SAME KV.
    const storeB = createSessionStore<{ nonce: string }>(kv, 600)
    expect(await storeB.get('sess-1')).toEqual({ nonce: 'abc' })
  })

  it('returns undefined after delete', async () => {
    const kv = makeSharedKv()
    const store = createSessionStore<{ x: number }>(kv, 600)
    await store.set('k', { x: 1 })
    await store.delete('k')
    expect(await store.get('k')).toBeUndefined()
  })

  it('returns undefined for a missing key', async () => {
    const store = createSessionStore<{ x: number }>(makeSharedKv(), 600)
    expect(await store.get('nope')).toBeUndefined()
  })

  it('falls back to an in-memory map when no KV is provided (stdio/local)', async () => {
    const store = createSessionStore<{ y: number }>(undefined, 600)
    await store.set('k', { y: 2 })
    expect(await store.get('k')).toEqual({ y: 2 })
  })

  it('treats an entry older than its TTL as absent', async () => {
    const kv = makeSharedKv()
    // TTL of 0 seconds: anything written is immediately stale on read.
    const store = createSessionStore<{ v: number }>(kv, 0)
    await store.set('k', { v: 9 })
    expect(await store.get('k')).toBeUndefined()
  })
})

describe('wrapKvBackendAsSessionKv', () => {
  // A Buffer-based backend matching the mcp-core CredentialBackend / CfKvBackend shape.
  function makeBufferBackend() {
    const store = new Map<string, Buffer>()
    return {
      store,
      backend: {
        async get(key: string): Promise<Buffer | null> {
          return store.get(key) ?? null
        },
        async put(key: string, blob: Buffer): Promise<void> {
          store.set(key, blob)
        },
        async delete(key: string): Promise<void> {
          store.delete(key)
        }
      }
    }
  }

  it('round-trips a string value through a Buffer-based backend', async () => {
    const { backend } = makeBufferBackend()
    const kv = wrapKvBackendAsSessionKv(backend)
    await kv.put('sess-1', '{"nonce":"abc"}')
    expect(await kv.get('sess-1')).toBe('{"nonce":"abc"}')
  })

  it('namespaces keys so OAuth state cannot collide with other KV data', async () => {
    const { store, backend } = makeBufferBackend()
    const kv = wrapKvBackendAsSessionKv(backend)
    await kv.put('raw-key', 'v')
    const storedKey = [...store.keys()][0]
    expect(storedKey).not.toBe('raw-key')
    expect(storedKey).toContain('raw-key')
  })

  it('returns null for a missing key and after delete', async () => {
    const { backend } = makeBufferBackend()
    const kv = wrapKvBackendAsSessionKv(backend)
    expect(await kv.get('nope')).toBeNull()
    await kv.put('k', 'v')
    await kv.delete('k')
    expect(await kv.get('k')).toBeNull()
  })

  it('accepts a caller-supplied key prefix so the store fits an app-scoped KV namespace allowlist', async () => {
    const { store, backend } = makeBufferBackend()
    const kv = wrapKvBackendAsSessionKv(backend, 'better-notion/delegated-oauth:')
    await kv.put('sess-1', 'v')
    const storedKey = [...store.keys()][0]
    expect(storedKey).toBe('better-notion/delegated-oauth:sess-1')
  })
})
