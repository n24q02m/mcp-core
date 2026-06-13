import { existsSync } from 'node:fs'
import * as fsPromises from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { acquireSessionLock, releaseSessionLock, setLockDir, writeSessionLock } from '../../src/storage/session-lock.js'

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  return {
    ...actual,
    unlink: vi.fn(actual.unlink),
    mkdir: vi.fn(actual.mkdir),
    readFile: vi.fn(actual.readFile)
  }
})

describe('session-lock coverage', () => {
  let tempDir: string

  beforeEach(async () => {
    tempDir = await fsPromises.mkdtemp(join(tmpdir(), 'mcp-lock-test-cov-'))
    setLockDir(tempDir)
    vi.clearAllMocks()
  })

  afterEach(async () => {
    setLockDir(null)
    await fsPromises.rm(tempDir, { recursive: true, force: true })
  })

  it('exercises DEFAULT_LOCK_DIR fallback in setLockDir(null)', async () => {
    setLockDir(null)
    const result = await acquireSessionLock('test-server')
    expect(result).toBeNull()
  })

  it('exercises mkdir in writeSessionLock when parent dir missing', async () => {
    const nestedDir = join(tempDir, 'nested/path')
    setLockDir(nestedDir)

    const info = {
      sessionId: 'test',
      relayUrl: 'http://test',
      createdAt: Date.now()
    }

    await writeSessionLock('test-server', info)
    expect(vi.mocked(fsPromises.mkdir)).toHaveBeenCalled()
    expect(existsSync(join(nestedDir, 'relay-session-test-server.lock'))).toBe(true)
  })

  it('exercises catch block in releaseSessionLock when unlink fails', async () => {
    const lockFile = join(tempDir, 'relay-session-test-server.lock')
    await fsPromises.writeFile(lockFile, 'test')

    vi.mocked(fsPromises.unlink).mockRejectedValueOnce(new Error('unlink failed'))

    // Should not throw
    await releaseSessionLock('test-server')
    expect(vi.mocked(fsPromises.unlink)).toHaveBeenCalled()
  })

  it('exercises inner catch in acquireSessionLock', async () => {
    // 1. Force readFile to throw to enter the outer catch block
    vi.mocked(fsPromises.readFile).mockRejectedValueOnce(new Error('read failed'))

    // 2. Force lockPath to throw inside releaseSessionLock by setting lockDirOverride to invalid type
    setLockDir(undefined as unknown as string)

    const result = await acquireSessionLock('test-server')
    expect(result).toBeNull()

    // Reset for afterEach
    setLockDir(tempDir)
  })
})
