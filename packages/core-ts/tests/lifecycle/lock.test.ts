import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import {
  DEFAULT_LOCK_TTL_HOURS,
  LifecycleLock,
  refreshLockTimestamp,
  sweepStaleLocks,
  writeLockFile
} from '../../src/lifecycle/lock.js'

let tmp: string

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'mcp-core-lock-'))
})

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true })
})

function writeLockWithAge(path: string, pid: number, port: number, ageHours = 0): void {
  const ts = new Date(Date.now() - ageHours * 3600 * 1000).toISOString()
  writeFileSync(path, `${pid}\n${port}\nproxy-token\n${ts}\n`)
}

describe('refreshLockTimestamp', () => {
  it('updates timestamp in 4-line lock', () => {
    const path = join(tmp, 'demo.lock')
    writeLockWithAge(path, 9999, 1234, 10)
    const beforeRaw = readFileSync(path, 'utf-8')
    const beforeTs = beforeRaw.split('\n')[3]

    refreshLockTimestamp(path)

    const afterRaw = readFileSync(path, 'utf-8')
    const afterTs = afterRaw.split('\n')[3]
    expect(new Date(afterTs).getTime()).toBeGreaterThan(new Date(beforeTs).getTime())
  })

  it('silent no-op on legacy 3-line lock', () => {
    const path = join(tmp, 'demo.lock')
    writeFileSync(path, '9999\n1234\ntoken\n')
    expect(() => refreshLockTimestamp(path)).not.toThrow()
    // Untouched
    const content = readFileSync(path, 'utf-8')
    expect(content.startsWith('9999\n1234\ntoken\n')).toBe(true)
  })

  it('silent no-op on missing file', () => {
    const path = join(tmp, 'missing.lock')
    expect(() => refreshLockTimestamp(path)).not.toThrow()
  })
})

describe('sweepStaleLocks', () => {
  it('removes expired lock', () => {
    const p = join(tmp, 'demo.lock')
    writeLockWithAge(p, process.pid, 2001, 25)

    expect(sweepStaleLocks('demo', 24, tmp)).toBe(1)
  })

  it('keeps lock within TTL', () => {
    const p = join(tmp, 'demo.lock')
    writeLockWithAge(p, process.pid, 3001, 1)

    expect(sweepStaleLocks('demo', 24, tmp)).toBe(0)
  })

  it('only targets named server', () => {
    const pDemo = join(tmp, 'demo.lock')
    const pOther = join(tmp, 'other-server.lock')
    writeLockWithAge(pDemo, 999999, 4001, 25)
    writeLockWithAge(pOther, 999999, 4002, 25)

    expect(sweepStaleLocks('demo', DEFAULT_LOCK_TTL_HOURS, tmp)).toBe(1)
  })

  it('removes legacy 3-line locks', () => {
    const p = join(tmp, 'demo.lock')
    writeFileSync(p, '9999\n5001\ntoken\n')

    expect(sweepStaleLocks('demo', DEFAULT_LOCK_TTL_HOURS, tmp)).toBe(1)
  })

  it('removes corrupted lock', () => {
    const p = join(tmp, 'demo.lock')
    writeFileSync(p, 'NOT_AN_INT\n1234\nt\n2026-04-28T19:00:00Z\n')

    expect(sweepStaleLocks('demo', DEFAULT_LOCK_TTL_HOURS, tmp)).toBe(1)
  })

  it('returns zero when locks dir missing', () => {
    expect(sweepStaleLocks('demo', DEFAULT_LOCK_TTL_HOURS, join(tmp, 'no-such-dir'))).toBe(0)
  })

  it('clears 11-stale-lock pile-up (regression for 2026-04-28 wet-mcp)', () => {
    // Test multiple DIFFERENT servers for the regression test
    for (let i = 0; i < 11; i++) {
      writeLockWithAge(join(tmp, `wet-mcp-${i}.lock`), 999990 + i, 50000 + i, 25)
    }
    let removed = 0
    for (let i = 0; i < 11; i++) {
      removed += sweepStaleLocks(`wet-mcp-${i}`, DEFAULT_LOCK_TTL_HOURS, tmp)
    }
    expect(removed).toBe(11)
  })

  it('default TTL is 24h', () => {
    expect(DEFAULT_LOCK_TTL_HOURS).toBe(24)
  })
})

describe('LifecycleLock', () => {
  it('acquires and releases', () => {
    const lock = new LifecycleLock('test', 9000, 'tok', tmp)
    lock.acquire()
    expect(existsSync(lock.path)).toBe(true)
    lock.release()
    expect(existsSync(lock.path)).toBe(false)
  })

  it('conflicts for same name', () => {
    const lockA = new LifecycleLock('test', 9000, 'tokA', tmp)
    const lockB = new LifecycleLock('test', 9001, 'tokB', tmp)
    lockA.acquire()
    expect(() => lockB.acquire()).toThrow(/another process/)
    lockA.release()
  })
})

describe('writeLockFile', () => {
  it('writes 4-line padded payload', () => {
    const path = writeLockFile('demo', 12345, 'tok', tmp)
    const raw = readFileSync(path, 'utf-8')
    const lines = raw.replace(/\n+$/, '').replace(/\s+$/, '').split('\n')
    expect(lines[0]).toBe(String(process.pid))
    expect(lines[1]).toBe('12345')
    expect(lines[2]).toBe('tok')
    expect(new Date(lines[3])).toBeInstanceOf(Date)
  })
})
