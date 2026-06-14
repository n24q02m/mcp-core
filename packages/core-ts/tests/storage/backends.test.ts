import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { backendFromEnv, CfKvBackend, type Http, InMemoryBackend, LocalFsBackend } from '../../src/storage/backends.js'
import { setHomeDirForTesting } from '../../src/storage/home-dir.js'
import { PerPluginStore } from '../../src/storage/per-plugin-store.js'

describe('InMemoryBackend', () => {
  it('put/get/delete roundtrip (absent get returns null)', async () => {
    const backend = new InMemoryBackend()
    expect(await backend.get('k')).toBeNull()
    await backend.put('k', Buffer.from([0, 1, 2]))
    expect(await backend.get('k')).toEqual(Buffer.from([0, 1, 2]))
    await backend.delete('k')
    expect(await backend.get('k')).toBeNull()
  })

  it('delete is idempotent', async () => {
    const backend = new InMemoryBackend()
    await backend.put('k', Buffer.from('data'))
    await backend.delete('k')
    expect(await backend.get('k')).toBeNull()
    await expect(backend.delete('k')).resolves.toBeUndefined()
  })
})

describe('LocalFsBackend', () => {
  let testHome: string

  beforeEach(() => {
    testHome = mkdtempSync(join(tmpdir(), 'backends-test-'))
    setHomeDirForTesting(testHome)
  })

  afterEach(() => {
    setHomeDirForTesting(null)
    rmSync(testHome, { recursive: true, force: true })
  })

  it('writes config blob under <home>/.<plugin>-mcp/config.json', async () => {
    const backend = new LocalFsBackend()
    await backend.put('wet/config', Buffer.from('blob'))
    const onDisk = readFileSync(join(testHome, '.wet-mcp', 'config.json'))
    expect(onDisk).toEqual(Buffer.from('blob'))
  })

  it('sub path get/delete roundtrip', async () => {
    const backend = new LocalFsBackend()
    await backend.put('wet/subs/u1/config', Buffer.from('blob'))
    const onDisk = readFileSync(join(testHome, '.wet-mcp', 'subs', 'u1', 'config.json'))
    expect(onDisk).toEqual(Buffer.from('blob'))
    expect(await backend.get('wet/subs/u1/config')).toEqual(Buffer.from('blob'))
    await backend.delete('wet/subs/u1/config')
    expect(await backend.get('wet/subs/u1/config')).toBeNull()
  })

  it('get returns null for absent key', async () => {
    const backend = new LocalFsBackend()
    expect(await backend.get('wet/config')).toBeNull()
  })

  it('rejects traversal in sub component', async () => {
    const backend = new LocalFsBackend()
    await expect(backend.put('wet/subs/../config', Buffer.from('x'))).rejects.toThrow()
    await expect(backend.get('wet/subs/../config')).rejects.toThrow()
    await expect(backend.delete('wet/subs/../config')).rejects.toThrow()
  })

  it('rejects traversal in plugin component', async () => {
    const backend = new LocalFsBackend()
    await expect(backend.put('../config', Buffer.from('x'))).rejects.toThrow()
  })

  it('allows a legitimate dot in sub', async () => {
    const backend = new LocalFsBackend()
    await backend.put('wet/subs/u.1/config', Buffer.from('blob'))
    expect(await backend.get('wet/subs/u.1/config')).toEqual(Buffer.from('blob'))
  })
})

describe('PerPluginStore with injected backend', () => {
  beforeEach(() => {
    process.env.CREDENTIAL_SECRET = 'test-master'
  })

  afterEach(() => {
    delete process.env.CREDENTIAL_SECRET
  })

  it('stores encrypted blob in the backend and loads it back', async () => {
    const mem = new InMemoryBackend()
    await new PerPluginStore('wet', 'u1', mem).save({ JINA_AI_API_KEY: 'k' })

    const stored = await mem.get('wet/subs/u1/config')
    expect(stored).not.toBeNull()

    // Ciphertext must differ from the plaintext JSON bytes (proves encryption ran).
    const plaintext = Buffer.from(JSON.stringify({ JINA_AI_API_KEY: 'k' }), 'utf-8')
    expect(stored).not.toEqual(plaintext)

    const loaded = await new PerPluginStore('wet', 'u1', mem).load()
    expect(loaded).toEqual({ JINA_AI_API_KEY: 'k' })
  })

  it('clear removes the blob from the backend', async () => {
    const mem = new InMemoryBackend()
    const store = new PerPluginStore('wet', 'u1', mem)
    await store.save({ k: 'v' })
    await store.clear()
    expect(await mem.get('wet/subs/u1/config')).toBeNull()
  })
})

/** In-memory HTTP stub keyed by the URL's last path segment; records PUT bodies. */
class FakeHttpStoring implements Http {
  store = new Map<string, Buffer>()

  async request(method: string, url: string, data?: Buffer): Promise<{ status: number; body: Buffer }> {
    const seg = url.slice(url.lastIndexOf('/') + 1)
    if (method === 'PUT') {
      this.store.set(seg, data ?? Buffer.alloc(0))
      return { status: 200, body: Buffer.alloc(0) }
    }
    if (method === 'GET') {
      const v = this.store.get(seg)
      return v ? { status: 200, body: v } : { status: 404, body: Buffer.alloc(0) }
    }
    if (method === 'DELETE') {
      this.store.delete(seg)
      return { status: 200, body: Buffer.alloc(0) }
    }
    throw new Error(`unexpected method ${method}`)
  }
}

/** HTTP stub returning a fixed status for any request. */
class StatusHttp implements Http {
  constructor(
    private status: number,
    private body: Buffer = Buffer.alloc(0)
  ) {}

  async request(): Promise<{ status: number; body: Buffer }> {
    return { status: this.status, body: this.body }
  }
}

describe('CfKvBackend', () => {
  it('roundtrip via a fake http stub', async () => {
    const fake = new FakeHttpStoring()
    const backend = new CfKvBackend('http://kv.internal', undefined, fake)
    expect(await backend.get('wet/config')).toBeNull()
    await backend.put('wet/config', Buffer.from('blob'))
    expect(await backend.get('wet/config')).toEqual(Buffer.from('blob'))
    await backend.delete('wet/config')
    expect(await backend.get('wet/config')).toBeNull()
  })

  it('get throws on 500', async () => {
    const backend = new CfKvBackend(
      'http://kv.internal',
      undefined,
      new StatusHttp(500, Buffer.from('<html>oops</html>'))
    )
    await expect(backend.get('wet/config')).rejects.toThrow()
  })

  it('get throws on 401', async () => {
    const backend = new CfKvBackend('http://kv.internal', undefined, new StatusHttp(401))
    await expect(backend.get('wet/config')).rejects.toThrow()
  })

  it('get returns null on 404', async () => {
    const backend = new CfKvBackend('http://kv.internal', undefined, new StatusHttp(404))
    expect(await backend.get('wet/config')).toBeNull()
  })

  it('delete throws on 500', async () => {
    const backend = new CfKvBackend('http://kv.internal', undefined, new StatusHttp(500))
    await expect(backend.delete('wet/config')).rejects.toThrow()
  })

  it('delete does not throw on 404', async () => {
    const backend = new CfKvBackend('http://kv.internal', undefined, new StatusHttp(404))
    await expect(backend.delete('wet/config')).resolves.toBeUndefined()
  })

  it('put throws on 500', async () => {
    const backend = new CfKvBackend('http://kv.internal', undefined, new StatusHttp(500))
    await expect(backend.put('wet/config', Buffer.from('x'))).rejects.toThrow()
  })

  it('propagates transport errors from get/put/delete', async () => {
    const throwingHttp: Http = {
      request: () => Promise.reject(new Error('econnrefused'))
    }
    const backend = new CfKvBackend('http://kv.internal', undefined, throwingHttp)
    await expect(backend.get('wet/config')).rejects.toThrow(/econnrefused/)
    await expect(backend.put('wet/config', Buffer.from('x'))).rejects.toThrow(/econnrefused/)
    await expect(backend.delete('wet/config')).rejects.toThrow(/econnrefused/)
  })
})

describe('backendFromEnv', () => {
  afterEach(() => {
    delete process.env.MCP_STORAGE_BACKEND
    delete process.env.MCP_KV_BASE_URL
    delete process.env.MCP_KV_TOKEN
  })

  it('default (no env) is LocalFsBackend', () => {
    delete process.env.MCP_STORAGE_BACKEND
    expect(backendFromEnv()).toBeInstanceOf(LocalFsBackend)
  })

  it('MCP_STORAGE_BACKEND=cf-kv is CfKvBackend', () => {
    process.env.MCP_STORAGE_BACKEND = 'cf-kv'
    process.env.MCP_KV_BASE_URL = 'http://kv.internal'
    expect(backendFromEnv()).toBeInstanceOf(CfKvBackend)
  })

  it('throws on an unknown backend kind', () => {
    process.env.MCP_STORAGE_BACKEND = 'bogus'
    expect(() => backendFromEnv()).toThrow()
  })

  it('cf-kv without MCP_KV_BASE_URL throws a clear error', () => {
    process.env.MCP_STORAGE_BACKEND = 'cf-kv'
    delete process.env.MCP_KV_BASE_URL
    expect(() => backendFromEnv()).toThrow(/MCP_KV_BASE_URL/)
  })
})
