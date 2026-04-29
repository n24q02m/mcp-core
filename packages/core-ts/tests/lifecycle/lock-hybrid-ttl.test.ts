/**
 * D9 — extended lock format (6 lines) + hybrid TTL sweep.
 *
 * Parity with `packages/core-py/tests/lifecycle/test_lock_hybrid_ttl.py`.
 * Cross-language behavior must stay identical so a daemon written in
 * one runtime can be swept by the other (rare, but possible during
 * mid-rollout when one MCP server still ships core-py while another
 * has migrated to core-ts).
 */

import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import * as lockModule from '../../src/lifecycle/lock.js'
import {
  LIFECYCLE_TTL_CONFIGURED_MS,
  LIFECYCLE_TTL_UNCONFIGURED_MS,
  type LockMetadata,
  parseLock,
  serializeLock,
  sweepStaleLocks
} from '../../src/lifecycle/lock.js'

let dir: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'mcp-locks-hybrid-'))
  vi.spyOn(lockModule, 'lockDir').mockReturnValue(dir)
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
  vi.restoreAllMocks()
})

function makeMeta(overrides: Partial<LockMetadata>): LockMetadata {
  const spawnedAt = overrides.spawnedAt ?? new Date()
  return {
    pid: 999,
    port: 1234,
    token: 't',
    spawnedAt,
    credState: 'configured',
    lastActivityAt: spawnedAt,
    createdAt: spawnedAt,
    ...overrides
  }
}

describe('serializeLock + parseLock (6-line format)', () => {
  it('serialize 6 lines', () => {
    const meta: LockMetadata = makeMeta({
      pid: 12345,
      port: 33333,
      token: 'abc-token',
      spawnedAt: new Date('2026-04-29T10:00:00Z'),
      credState: 'configured',
      lastActivityAt: new Date('2026-04-29T11:00:00Z')
    })
    const lines = serializeLock(meta).split('\n')
    expect(lines[0]).toBe('12345')
    expect(lines[1]).toBe('33333')
    expect(lines[2]).toBe('abc-token')
    expect(lines[3]).toBe('2026-04-29T10:00:00.000Z')
    expect(lines[4]).toBe('configured')
    expect(lines[5]).toBe('2026-04-29T11:00:00.000Z')
  })

  it('parse 6 lines modern', () => {
    const raw = '12345\n33333\nabc-token\n2026-04-29T10:00:00.000Z\nconfigured\n2026-04-29T11:00:00.000Z\n'
    const meta = parseLock(raw)
    expect(meta.pid).toBe(12345)
    expect(meta.credState).toBe('configured')
  })

  it('parse 4 lines legacy assumes configured', () => {
    const raw = '12345\n33333\nabc-token\n2026-04-29T10:00:00.000Z\n'
    const meta = parseLock(raw)
    expect(meta.credState).toBe('configured')
    expect(meta.lastActivityAt.getTime()).toBe(meta.spawnedAt.getTime())
  })
})

describe('sweepStaleLocks (D9 hybrid TTL)', () => {
  it('removes unconfigured > 30 min', () => {
    vi.spyOn(lockModule, 'isAlive').mockReturnValue(true)
    const terminateSpy = vi.spyOn(lockModule, 'terminateDaemon').mockImplementation(() => {})

    const old = new Date(Date.now() - 31 * 60_000)
    writeFileSync(
      join(dir, 'demo-1234.lock'),
      serializeLock(
        makeMeta({
          pid: 999,
          port: 1234,
          token: 't',
          spawnedAt: old,
          credState: 'unconfigured',
          lastActivityAt: old
        })
      )
    )

    expect(sweepStaleLocks('demo')).toBe(1)
    expect(existsSync(join(dir, 'demo-1234.lock'))).toBe(false)
    expect(terminateSpy).toHaveBeenCalledWith(999)
  })

  it('keeps configured under 24h', () => {
    vi.spyOn(lockModule, 'isAlive').mockReturnValue(true)
    vi.spyOn(lockModule, 'terminateDaemon').mockImplementation(() => {})

    const fresh = new Date(Date.now() - 23 * 3600_000)
    writeFileSync(
      join(dir, 'demo-1234.lock'),
      serializeLock(
        makeMeta({
          pid: 999,
          port: 1234,
          token: 't',
          spawnedAt: fresh,
          credState: 'configured',
          lastActivityAt: fresh
        })
      )
    )

    expect(sweepStaleLocks('demo')).toBe(0)
    expect(existsSync(join(dir, 'demo-1234.lock'))).toBe(true)
  })

  it('removes dead immediately', () => {
    vi.spyOn(lockModule, 'isAlive').mockReturnValue(false)
    vi.spyOn(lockModule, 'terminateDaemon').mockImplementation(() => {})

    const fresh = new Date(Date.now() - 5 * 60_000)
    writeFileSync(
      join(dir, 'demo-1234.lock'),
      serializeLock(
        makeMeta({
          pid: 999,
          port: 1234,
          token: 't',
          spawnedAt: fresh,
          credState: 'configured',
          lastActivityAt: fresh
        })
      )
    )

    expect(sweepStaleLocks('demo')).toBe(1)
    expect(existsSync(join(dir, 'demo-1234.lock'))).toBe(false)
  })
})

describe('TTL constants', () => {
  it('configured TTL is 24h in ms', () => {
    expect(LIFECYCLE_TTL_CONFIGURED_MS).toBe(24 * 3600 * 1000)
  })
  it('unconfigured TTL is 30 min in ms', () => {
    expect(LIFECYCLE_TTL_UNCONFIGURED_MS).toBe(30 * 60 * 1000)
  })
})
