import { existsSync, writeFileSync } from 'node:fs'
import * as fsPromises from 'node:fs/promises'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  acquireSessionLock,
  releaseSessionLock,
  type SessionInfo,
  setLockDir,
  writeSessionLock
} from '../../src/storage/session-lock.js'

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  return {
    ...actual,
    unlink: vi.fn(actual.unlink),
    readFile: vi.fn(actual.readFile),
    mkdir: vi.fn(actual.mkdir)
  }
})

let tempDir: string

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'mcp-lock-coverage-test-'))
  setLockDir(tempDir)
  vi.clearAllMocks()
})

afterEach(async () => {
  setLockDir(null)
  await rm(tempDir, { recursive: true, force: true })
})

describe('session-lock coverage', () => {
  it('covers DEFAULT_LOCK_DIR branch in getLockDir', async () => {
    setLockDir(null)
    // Should use DEFAULT_LOCK_DIR, we just want to ensure it doesn't throw and hits line 29
    await acquireSessionLock('test-server')
  })

  it('covers mkdir branch in writeSessionLock', async () => {
    const nestedDir = join(tempDir, 'nested-dir-to-create')
    setLockDir(nestedDir)

    const info: SessionInfo = {
      sessionId: 'abc',
      relayUrl: 'https://example.com',
      createdAt: Date.now()
    }

    await writeSessionLock('test-server', info)
    expect(existsSync(nestedDir)).toBe(true)
  })

  it('covers catch block in releaseSessionLock', async () => {
    const lockFile = join(tempDir, 'relay-session-error.lock')
    writeFileSync(lockFile, 'data')

    vi.mocked(fsPromises.unlink).mockRejectedValueOnce(new Error('unlink failed'))

    // Should not throw because releaseSessionLock has its own try-catch
    await releaseSessionLock('error')
    expect(existsSync(lockFile)).toBe(true)
  })

  it('covers outer catch block in acquireSessionLock', async () => {
    const lockFile = join(tempDir, 'relay-session-outer.lock')
    writeFileSync(lockFile, 'data')

    vi.mocked(fsPromises.readFile).mockRejectedValueOnce(new Error('read failed'))

    const result = await acquireSessionLock('outer')
    expect(result).toBeNull()
    // Should have called releaseSessionLock which unlinks the file
    expect(existsSync(lockFile)).toBe(false)
  })

  it('covers inner catch block in acquireSessionLock', async () => {
    const lockFile = join(tempDir, 'relay-session-inner.lock')
    writeFileSync(lockFile, 'data')

    vi.mocked(fsPromises.readFile).mockImplementationOnce(async () => {
      // Make subsequent lockPath calls throw by setting an invalid type
      setLockDir(123 as unknown as string)
      throw new Error('read failed')
    })

    const result = await acquireSessionLock('inner')
    expect(result).toBeNull()
  })
})
