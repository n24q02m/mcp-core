import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import {
  DEFAULT_LOCK_TTL_HOURS,
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
  it('updates timestamp in 4-line lock', async () => {
    const path = join(tmp, 'demo-1234.lock')
    writeLockWithAge(path, 9999, 1234, 10)
    const beforeRaw = readFileSync(path, 'utf-8')
    const beforeTs = beforeRaw.split('\n')[3]

    await refreshLockTimestamp(path)

    const afterRaw = readFileSync(path, 'utf-8')
    const afterTs = afterRaw.split('\n')[3]
    expect(new Date(afterTs).getTime()).toBeGreaterThan(new Date(beforeTs).getTime())
  })

  it('silent no-op on legacy 3-line lock', async () => {
    const path = join(tmp, 'demo-1234.lock')
    writeFileSync(path, '9999\n1234\ntoken\n')
    await expect(refreshLockTimestamp(path)).resolves.not.toThrow()
    // Untouched
    const content = readFileSync(path, 'utf-8')
    expect(content.startsWith('9999\n1234\ntoken\n')).toBe(true)
  })

  it('silent no-op on missing file', async () => {
    const path = join(tmp, 'missing.lock')
    await expect(refreshLockTimestamp(path)).resolves.not.toThrow()
  })
})

describe('sweepStaleLocks', () => {
  it('removes expired lock', async () => {
    const p = join(tmp, 'demo-2001.lock')
    writeLockWithAge(p, process.pid, 2001, 25)

    expect(await sweepStaleLocks('demo', 24, tmp)).toBe(1)
  })

  it('keeps lock within TTL', async () => {
    const p = join(tmp, 'demo-3001.lock')
    writeLockWithAge(p, process.pid, 3001, 1)

    expect(await sweepStaleLocks('demo', 24, tmp)).toBe(0)
  })

  it('only targets named server', async () => {
    const pDemo = join(tmp, 'demo-4001.lock')
    const pOther = join(tmp, 'other-server-4002.lock')
    writeLockWithAge(pDemo, 999999, 4001, 25)
    writeLockWithAge(pOther, 999999, 4002, 25)

    expect(await sweepStaleLocks('demo', DEFAULT_LOCK_TTL_HOURS, tmp)).toBe(1)
  })

  it('removes legacy 3-line locks', async () => {
    const p = join(tmp, 'demo-5001.lock')
    writeFileSync(p, '9999\n5001\ntoken\n')

    expect(await sweepStaleLocks('demo', DEFAULT_LOCK_TTL_HOURS, tmp)).toBe(1)
  })

  it('removes corrupted lock', async () => {
    const p = join(tmp, 'demo-6001.lock')
    writeFileSync(p, 'NOT_AN_INT\n1234\nt\n2026-04-28T19:00:00Z\n')

    expect(await sweepStaleLocks('demo', DEFAULT_LOCK_TTL_HOURS, tmp)).toBe(1)
  })

  it('returns zero when locks dir missing', async () => {
    expect(await sweepStaleLocks('demo', DEFAULT_LOCK_TTL_HOURS, join(tmp, 'no-such-dir'))).toBe(0)
  })

  it('clears 11-stale-lock pile-up (regression for 2026-04-28 wet-mcp)', async () => {
    for (let i = 0; i < 11; i++) {
      writeLockWithAge(join(tmp, `wet-mcp-${50000 + i}.lock`), 999990 + i, 50000 + i, 25)
    }
    expect(await sweepStaleLocks('wet-mcp', DEFAULT_LOCK_TTL_HOURS, tmp)).toBe(11)
  })

  it('default TTL is 24h', () => {
    expect(DEFAULT_LOCK_TTL_HOURS).toBe(24)
  })
})

describe('writeLockFile', () => {
  it('writes 4-line padded payload', async () => {
    const path = await writeLockFile('demo', 12345, 'tok', tmp)
    const raw = readFileSync(path, 'utf-8')
    const lines = raw.replace(/\n+$/, '').replace(/\s+$/, '').split('\n')
    expect(lines[0]).toBe(String(process.pid))
    expect(lines[1]).toBe('12345')
    expect(lines[2]).toBe('tok')
    expect(new Date(lines[3])).toBeInstanceOf(Date)
  })
})
