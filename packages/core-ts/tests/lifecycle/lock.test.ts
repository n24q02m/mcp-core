import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import {
  DEFAULT_LOCK_TTL_HOURS,
  isLockExpired,
  isPidAlive,
  parseLockMetadata,
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

describe('parseLockMetadata', () => {
  it('returns null for missing file', () => {
    expect(parseLockMetadata(join(tmp, 'missing.lock'))).toBeNull()
  })

  it('returns null for legacy 3-line lock', () => {
    const path = join(tmp, 'demo-1234.lock')
    writeFileSync(path, '9999\n1234\ntoken\n')
    expect(parseLockMetadata(path)).toBeNull()
  })

  it('returns null for corrupted pid', () => {
    const path = join(tmp, 'demo-1234.lock')
    writeFileSync(path, 'NOT_AN_INT\n1234\nt\n2026-04-28T19:00:00Z\n')
    expect(parseLockMetadata(path)).toBeNull()
  })

  it('parses 4-line format', () => {
    const path = join(tmp, 'demo-1234.lock')
    writeLockWithAge(path, 9999, 1234)
    const md = parseLockMetadata(path)
    expect(md).not.toBeNull()
    expect(md!.pid).toBe(9999)
    expect(md!.port).toBe(1234)
    expect(md!.token).toBe('proxy-token')
    expect(md!.createdAt).toBeInstanceOf(Date)
  })
})

describe('isLockExpired', () => {
  it('expired after 24h default', () => {
    const path = join(tmp, 'demo-1234.lock')
    writeLockWithAge(path, 9999, 1234, 25)
    expect(isLockExpired(path)).toBe(true)
  })

  it('not expired within 24h', () => {
    const path = join(tmp, 'demo-1234.lock')
    writeLockWithAge(path, 9999, 1234, 23)
    expect(isLockExpired(path)).toBe(false)
  })

  it('legacy locks treated as expired', () => {
    const path = join(tmp, 'demo-1234.lock')
    writeFileSync(path, '9999\n1234\ntoken\n')
    expect(isLockExpired(path)).toBe(true)
  })

  it('default TTL is 24h', () => {
    expect(DEFAULT_LOCK_TTL_HOURS).toBe(24)
  })
})

describe('isPidAlive', () => {
  it('detects own process as alive', () => {
    expect(isPidAlive(process.pid)).toBe(true)
  })

  it('detects very high PID as dead', () => {
    expect(isPidAlive(999999)).toBe(false)
  })

  it('returns false for non-positive pid', () => {
    expect(isPidAlive(0)).toBe(false)
    expect(isPidAlive(-1)).toBe(false)
  })
})

describe('refreshLockTimestamp', () => {
  it('updates timestamp in 4-line lock', () => {
    const path = join(tmp, 'demo-1234.lock')
    writeLockWithAge(path, 9999, 1234, 10)
    const before = parseLockMetadata(path)!.createdAt.getTime()

    refreshLockTimestamp(path)

    const after = parseLockMetadata(path)!.createdAt.getTime()
    expect(after).toBeGreaterThan(before)
  })

  it('silent no-op on legacy lock', () => {
    const path = join(tmp, 'demo-1234.lock')
    writeFileSync(path, '9999\n1234\ntoken\n')
    expect(() => refreshLockTimestamp(path)).not.toThrow()
    // Untouched
    const content = readFileSync(path, 'utf-8')
    expect(content.startsWith('9999\n1234\ntoken\n')).toBe(true)
  })
})

describe('sweepStaleLocks', () => {
  it('removes locks with dead pid', () => {
    const p1 = join(tmp, 'demo-1001.lock')
    const p2 = join(tmp, 'demo-1002.lock')
    writeLockWithAge(p1, 999999, 1001)
    writeLockWithAge(p2, 999998, 1002)

    expect(sweepStaleLocks('demo', DEFAULT_LOCK_TTL_HOURS, tmp)).toBe(2)
  })

  it('removes expired lock even if pid alive', () => {
    const p = join(tmp, 'demo-2001.lock')
    writeLockWithAge(p, process.pid, 2001, 25)

    expect(sweepStaleLocks('demo', 24, tmp)).toBe(1)
  })

  it('keeps alive lock within TTL', () => {
    const p = join(tmp, 'demo-3001.lock')
    writeLockWithAge(p, process.pid, 3001, 1)

    expect(sweepStaleLocks('demo', 24, tmp)).toBe(0)
  })

  it('only targets named server', () => {
    const pDemo = join(tmp, 'demo-4001.lock')
    const pOther = join(tmp, 'other-server-4002.lock')
    writeLockWithAge(pDemo, 999999, 4001)
    writeLockWithAge(pOther, 999999, 4002)

    expect(sweepStaleLocks('demo', DEFAULT_LOCK_TTL_HOURS, tmp)).toBe(1)
  })

  it('removes legacy 3-line locks', () => {
    const p = join(tmp, 'demo-5001.lock')
    writeFileSync(p, '9999\n5001\ntoken\n')

    expect(sweepStaleLocks('demo', DEFAULT_LOCK_TTL_HOURS, tmp)).toBe(1)
  })

  it('returns zero when locks dir missing', () => {
    expect(sweepStaleLocks('demo', DEFAULT_LOCK_TTL_HOURS, join(tmp, 'no-such-dir'))).toBe(0)
  })

  it('clears 11-stale-lock pile-up (regression for 2026-04-28 wet-mcp)', () => {
    for (let i = 0; i < 11; i++) {
      writeLockWithAge(join(tmp, `wet-mcp-${50000 + i}.lock`), 999990 + i, 50000 + i)
    }
    expect(sweepStaleLocks('wet-mcp', DEFAULT_LOCK_TTL_HOURS, tmp)).toBe(11)
  })
})

describe('writeLockFile', () => {
  it('writes 4-line padded payload', () => {
    const path = writeLockFile('demo', 12345, 'tok', tmp)
    const md = parseLockMetadata(path)
    expect(md).not.toBeNull()
    expect(md!.pid).toBe(process.pid)
    expect(md!.port).toBe(12345)
    expect(md!.token).toBe('tok')
  })
})
