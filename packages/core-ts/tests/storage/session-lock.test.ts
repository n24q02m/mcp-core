import { existsSync } from 'node:fs'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  return {
    ...actual,
    readFile: vi.fn(actual.readFile),
    unlink: vi.fn(actual.unlink),
    mkdir: vi.fn(actual.mkdir),
    writeFile: vi.fn(actual.writeFile),
    rename: vi.fn(actual.rename)
  }
})

import * as fsPromises from 'node:fs/promises'
import {
  acquireSessionLock,
  releaseSessionLock,
  type SessionInfo,
  setLockDir,
  writeSessionLock
} from '../../src/storage/session-lock.js'

let tempDir: string

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'mcp-lock-test-'))
  setLockDir(tempDir)
})

afterEach(async () => {
  setLockDir(null)
  await rm(tempDir, { recursive: true, force: true })
  vi.clearAllMocks()
})

describe('acquireSessionLock', () => {
  it('returns null when no lock exists', async () => {
    const result = await acquireSessionLock('test-server')
    expect(result).toBeNull()
  })

  it('returns session info when lock is fresh', async () => {
    const info: SessionInfo = {
      sessionId: 'abc123',
      relayUrl: 'https://relay.example.com/authorize?s=abc123#k=key&p=pass',
      createdAt: Date.now()
    }
    await writeSessionLock('test-server', info)

    const result = await acquireSessionLock('test-server')
    expect(result).not.toBeNull()
    expect(result?.sessionId).toBe('abc123')
    expect(result?.relayUrl).toBe(info.relayUrl)
    expect(result?.createdAt).toBe(info.createdAt)
  })

  it('returns null when lock is expired', async () => {
    const info: SessionInfo = {
      sessionId: 'old-session',
      relayUrl: 'https://relay.example.com/authorize?s=old',
      createdAt: Date.now() - 700_000 // 700s ago (> 600s default)
    }
    await writeSessionLock('test-server', info)

    const result = await acquireSessionLock('test-server')
    expect(result).toBeNull()

    // Lock file should be cleaned up
    expect(existsSync(join(tempDir, 'relay-session-test-server.lock'))).toBe(false)
  })

  it('respects custom max age', async () => {
    const info: SessionInfo = {
      sessionId: 'short-lived',
      relayUrl: 'https://relay.example.com/authorize?s=short',
      createdAt: Date.now() - 5000 // 5 seconds ago
    }
    await writeSessionLock('test-server', info)

    // Should be expired with 3s max age
    expect(await acquireSessionLock('test-server', 3000)).toBeNull()

    // Rewrite since it was cleaned up
    const info2: SessionInfo = {
      sessionId: 'short-lived-2',
      relayUrl: 'https://relay.example.com/authorize?s=short2',
      createdAt: Date.now() - 5000
    }
    await writeSessionLock('test-server', info2)

    // Should be valid with 10s max age
    const result = await acquireSessionLock('test-server', 10_000)
    expect(result).not.toBeNull()
    expect(result?.sessionId).toBe('short-lived-2')
  })

  it('returns null on corrupt lock file', async () => {
    const lockFile = join(tempDir, 'relay-session-test-server.lock')
    await writeFile(lockFile, 'not valid json', 'utf-8')

    const result = await acquireSessionLock('test-server')
    expect(result).toBeNull()

    // Corrupt file should be cleaned up
    expect(existsSync(lockFile)).toBe(false)
  })

  it('returns null on missing fields', async () => {
    const lockFile = join(tempDir, 'relay-session-test-server.lock')
    await writeFile(lockFile, JSON.stringify({ session_id: 'partial' }), 'utf-8')

    const result = await acquireSessionLock('test-server')
    expect(result).toBeNull()
  })

  it('returns null and cleans up on readFile error', async () => {
    const info: SessionInfo = {
      sessionId: 'read-error',
      relayUrl: 'https://relay.example.com/error',
      createdAt: Date.now()
    }
    await writeSessionLock('test-server', info)
    const lockFile = join(tempDir, 'relay-session-test-server.lock')
    expect(existsSync(lockFile)).toBe(true)

    vi.mocked(fsPromises.readFile).mockRejectedValueOnce(new Error('Read failed'))

    const result = await acquireSessionLock('test-server')
    expect(result).toBeNull()
    // Should have called releaseSessionLock which unlinks the file
    expect(existsSync(lockFile)).toBe(false)
  })

  it('handles errors during releaseSessionLock within acquireSessionLock', async () => {
    const lockFile = join(tempDir, 'relay-session-test-server.lock')
    await writeFile(lockFile, 'not valid json', 'utf-8')

    // Force readFile to fail to trigger the catch block in acquireSessionLock
    vi.mocked(fsPromises.readFile).mockRejectedValueOnce(new Error('Read failed'))

    // Force unlink to fail to trigger the inner catch block
    const unlinkSpy = vi.mocked(fsPromises.unlink).mockRejectedValueOnce(new Error('Unlink failed'))

    const result = await acquireSessionLock('test-server')
    expect(result).toBeNull()
    expect(unlinkSpy).toHaveBeenCalled()
  })
})

describe('writeSessionLock', () => {
  it('creates directory if it does not exist', async () => {
    const subDir = join(tempDir, 'nested/dir')
    setLockDir(subDir)
    const info: SessionInfo = {
      sessionId: 'nested-session',
      relayUrl: 'https://relay.example.com/nested',
      createdAt: Date.now()
    }
    await writeSessionLock('test-server', info)

    const lockFile = join(subDir, 'relay-session-test-server.lock')
    expect(existsSync(lockFile)).toBe(true)
  })

  it('creates lock file with correct format', async () => {
    const info: SessionInfo = {
      sessionId: 'new-session',
      relayUrl: 'https://relay.example.com/authorize?s=new',
      createdAt: 1234567890000
    }
    await writeSessionLock('test-server', info)

    const lockFile = join(tempDir, 'relay-session-test-server.lock')
    expect(existsSync(lockFile)).toBe(true)

    const data = JSON.parse(await readFile(lockFile, 'utf-8'))
    expect(data).toEqual({
      session_id: 'new-session',
      relay_url: 'https://relay.example.com/authorize?s=new',
      created_at: 1234567890000
    })
  })

  it('overwrites existing lock', async () => {
    const now = Date.now()
    const info1: SessionInfo = { sessionId: 'first', relayUrl: 'https://first', createdAt: now }
    await writeSessionLock('test-server', info1)

    const info2: SessionInfo = { sessionId: 'second', relayUrl: 'https://second', createdAt: now }
    await writeSessionLock('test-server', info2)

    const result = await acquireSessionLock('test-server')
    expect(result).not.toBeNull()
    expect(result?.sessionId).toBe('second')
  })
})

describe('releaseSessionLock', () => {
  it('removes lock file', async () => {
    const info: SessionInfo = {
      sessionId: 'to-release',
      relayUrl: 'https://relay.example.com/release',
      createdAt: Date.now()
    }
    await writeSessionLock('test-server', info)

    const lockFile = join(tempDir, 'relay-session-test-server.lock')
    expect(existsSync(lockFile)).toBe(true)

    await releaseSessionLock('test-server')
    expect(existsSync(lockFile)).toBe(false)
  })

  it('no error when lock does not exist', async () => {
    // Should not throw
    await releaseSessionLock('nonexistent-server')
  })

  it('different servers have independent locks', async () => {
    const infoA: SessionInfo = { sessionId: 'server-a', relayUrl: 'https://a', createdAt: Date.now() }
    const infoB: SessionInfo = { sessionId: 'server-b', relayUrl: 'https://b', createdAt: Date.now() }
    await writeSessionLock('server-a', infoA)
    await writeSessionLock('server-b', infoB)

    await releaseSessionLock('server-a')

    expect(await acquireSessionLock('server-a')).toBeNull()
    const resultB = await acquireSessionLock('server-b')
    expect(resultB).not.toBeNull()
    expect(resultB?.sessionId).toBe('server-b')
  })
})

describe('getLockDir', () => {
  it('uses default lock dir when override is null', async () => {
    setLockDir(null)
    // We can't easily check the path without duplicating logic,
    // but we can verify it doesn't throw and uses some path.
    const result = await acquireSessionLock('test-server')
    expect(result).toBeNull()
  })
})
