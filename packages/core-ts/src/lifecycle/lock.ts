/**
 * Lock-file lifecycle helpers (D9 — hybrid TTL extension).
 *
 * The lock file written by `runLocalServer` may contain 4 lines (legacy
 * v1) or 6 lines (D9 modern):
 *
 * ```
 * {pid}
 * {port}
 * {token}
 * {spawnedAt_iso8601_utc}
 * {credState}                    # "configured" | "unconfigured" (D9)
 * {lastActivityAt_iso8601_utc}   # bumped by daemon refresh loop (D9)
 * ```
 *
 * Stale locks are detected when *any* of:
 *  - file has legacy 3-line format (no timestamp) → migrate by deletion
 *  - timestamp older than the applicable TTL
 *      - configured credState → 24h
 *      - unconfigured credState → 30 min
 *  - writing PID does not exist on this host
 *
 * Dead-PID locks are reaped immediately. Past-TTL idle setup daemons
 * (unconfigured) are terminated; configured daemons past TTL get their
 * lock unlinked but the process is left alone (parity with pre-D9 sweep
 * behavior so a long-running daemon never gets SIGKILL'd by a sweep
 * race).
 *
 * TypeScript port of core-py's `mcp_core.lifecycle.lock`. Behaviour and
 * TTL constants kept identical for cross-language parity.
 */

import { existsSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

// Self-import so `sweepStaleLocks` can resolve `lockDir`/`isAlive`/
// `terminateDaemon` through the module namespace at call time. This
// makes `vi.spyOn(lockModule, '<name>').mockReturnValue(...)` actually
// intercept the helper from inside the sweep loop — without this
// indirection, the closure-captured local binding ignores spies and
// test mocks become silent no-ops.
import * as self from './lock.js'

export const DEFAULT_LOCK_TTL_HOURS = 24

/** D9 hybrid TTL constants — selected by `credState` in `sweepStaleLocks`. */
export const LIFECYCLE_TTL_CONFIGURED_MS = 24 * 3600 * 1000
export const LIFECYCLE_TTL_UNCONFIGURED_MS = 30 * 60 * 1000

export type CredState = 'configured' | 'unconfigured'

/**
 * Parsed lock metadata. `createdAt` is preserved as a backward-compat
 * alias for `spawnedAt` so pre-D9 callers (test_lock format suite,
 * `refreshLockTimestamp`) continue to work without source changes.
 */
export interface LockMetadata {
  pid: number
  port: number
  token: string
  spawnedAt: Date
  credState: CredState
  lastActivityAt: Date
  /** @deprecated Alias for `spawnedAt`. New code should read `spawnedAt`. */
  createdAt: Date
}

export function locksDir(root?: string): string {
  return root ?? join(homedir(), '.config', 'mcp', 'locks')
}

/**
 * No-arg lock-dir resolver — D9 sweep tests `vi.spyOn(lockModule, 'lockDir')`
 * to redirect into a temp directory without threading a `root` arg.
 */
export function lockDir(): string {
  return locksDir()
}

/**
 * Serialize `LockMetadata` to the 6-line on-disk format. Trailing
 * newline included so writes always end in `\n` and the parser's
 * `lines.length` checks behave deterministically.
 */
export function serializeLock(meta: LockMetadata): string {
  return [
    String(meta.pid),
    String(meta.port),
    meta.token,
    meta.spawnedAt.toISOString(),
    meta.credState,
    meta.lastActivityAt.toISOString(),
    ''
  ].join('\n')
}

/**
 * Parse the textual lock payload into `LockMetadata`. Accepts 4-line
 * legacy, 5-line transitional, and 6-line D9 modern formats. Throws on
 * fewer than 4 lines or unparseable timestamp / pid / port.
 */
export function parseLock(raw: string): LockMetadata {
  const lines = raw.replace(/\n+$/, '').split('\n')
  if (lines.length < 4) throw new Error(`lock file too few lines: ${lines.length}`)
  const pid = Number(lines[0])
  const port = Number(lines[1])
  if (!Number.isInteger(pid) || !Number.isInteger(port)) {
    throw new Error(`lock file has non-integer pid/port`)
  }
  const token = lines[2]
  const spawnedAt = new Date(lines[3])
  if (Number.isNaN(spawnedAt.getTime())) {
    throw new Error(`lock file has unparseable spawnedAt`)
  }
  let credState: CredState = 'configured'
  let lastActivityAt = spawnedAt
  if (lines.length >= 6) {
    credState = lines[4] as CredState
    lastActivityAt = new Date(lines[5])
    if (Number.isNaN(lastActivityAt.getTime())) lastActivityAt = spawnedAt
  } else if (lines.length === 5) {
    credState = lines[4] as CredState
  }
  return { pid, port, token, spawnedAt, credState, lastActivityAt, createdAt: spawnedAt }
}

export function parseLockMetadata(path: string): LockMetadata | null {
  if (!existsSync(path)) return null
  let content: string
  try {
    content = readFileSync(path, { encoding: 'utf-8' })
  } catch {
    return null
  }
  const lines = content.trim().split('\n')
  // Pre-D9 callers expect null for legacy 3-line format. The new
  // `parseLock` instead throws — adapter logic here keeps both
  // contracts: legacy / corrupt -> null; valid 4/5/6-line -> populated.
  if (lines.length < 4) return null
  try {
    return parseLock(content)
  } catch {
    return null
  }
}

export function isLockExpired(path: string, ttlHours: number = DEFAULT_LOCK_TTL_HOURS): boolean {
  const md = parseLockMetadata(path)
  if (md === null) return true
  const ageMs = Date.now() - md.spawnedAt.getTime()
  return ageMs > ttlHours * 3600 * 1000
}

/**
 * Cross-platform PID liveness check via `process.kill(pid, 0)`. Best-effort.
 * Returns false on EPERM (different-user processes) so sweep does not steal
 * locks owned by other users. Pre-D9 entry point — kept for backward compat.
 */
export function isPidAlive(pid: number): boolean {
  if (pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code
    if (code === 'EPERM') return true // exists but we lack permission
    return false
  }
}

/**
 * Liveness check on a parsed `LockMetadata`. D9 sweep tests
 * `vi.spyOn(lockModule, 'isAlive')` to control the alive/dead branch
 * without needing a real PID. Wraps `isPidAlive` so the underlying
 * cross-platform logic stays in one place.
 */
export function isAlive(meta: LockMetadata): boolean {
  return isPidAlive(meta.pid)
}

/**
 * Kill the lock owner. D9 sweep tests `vi.spyOn(lockModule, 'terminateDaemon')`
 * to assert the unconfigured-TTL branch invokes termination, without
 * killing real PIDs. Used by `sweepStaleLocks` when an unconfigured
 * daemon's idle TTL elapses.
 */
export function terminateDaemon(pid: number): void {
  if (pid <= 0) return
  try {
    process.kill(pid, 'SIGKILL')
  } catch {
    /* ignore */
  }
}

/**
 * Refresh `spawnedAt` of an existing lock file. Silent no-op on legacy /
 * malformed files so callers don't need try/except.
 *
 * Padded to 512 bytes so on-disk size stays stable while a Windows
 * byte-range lock is held past the metadata region (parity with core-py).
 * Preserves the on-disk line count: a 4-line legacy lock stays 4-line
 * after refresh; a 6-line modern lock stays 6-line (with both `spawnedAt`
 * and `lastActivityAt` bumped).
 */
export function refreshLockTimestamp(path: string): void {
  const md = parseLockMetadata(path)
  if (md === null) return
  let raw: string
  try {
    raw = readFileSync(path, { encoding: 'utf-8' })
  } catch {
    return
  }
  const lineCount = raw.trim().split('\n').length
  const now = new Date().toISOString()
  let payload: string
  if (lineCount >= 6) {
    payload = `${md.pid}\n${md.port}\n${md.token}\n${now}\n${md.credState}\n${now}\n`
  } else {
    payload = `${md.pid}\n${md.port}\n${md.token}\n${now}\n`
  }
  try {
    writeFileSync(path, payload.padEnd(512, ' '), { encoding: 'utf-8' })
  } catch {
    // Best-effort
  }
}

/**
 * Remove stale lock files for `serverName` (D9 hybrid TTL). Returns count removed.
 *
 * Called by `runLocalServer` at daemon startup before writing its own lock,
 * preventing pile-up of dozens of `<server>-<port>.lock` files when daemons
 * exit abnormally (Windows OOM, taskkill, signal).
 *
 * Backward-compat: the legacy signature `(serverName, ttlHours, root)` is
 * preserved for pre-D9 callers. New D9 callers pass just `serverName` and
 * rely on the hybrid TTL plus the `lockDir()` lookup (mockable in tests).
 */
export function sweepStaleLocks(serverName: string, ttlHours?: number, root?: string): number {
  const dir = root !== undefined ? root : self.lockDir()
  if (!existsSync(dir)) return 0

  let removed = 0
  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return 0
  }

  const prefix = `${serverName}-`
  const suffix = '.lock'
  const now = Date.now()
  const configuredTtlMs = (ttlHours ?? DEFAULT_LOCK_TTL_HOURS) * 3600 * 1000

  for (const entry of entries) {
    if (!entry.startsWith(prefix) || !entry.endsWith(suffix)) continue
    const full = join(dir, entry)
    let raw: string
    try {
      raw = readFileSync(full, { encoding: 'utf-8' })
    } catch {
      try {
        unlinkSync(full)
        removed += 1
      } catch {
        /* ignore */
      }
      continue
    }
    let meta: LockMetadata
    try {
      meta = parseLock(raw)
    } catch {
      try {
        unlinkSync(full)
        removed += 1
      } catch {
        /* ignore */
      }
      continue
    }
    if (!self.isAlive(meta)) {
      try {
        unlinkSync(full)
        removed += 1
      } catch {
        /* ignore */
      }
      continue
    }
    const ttlMs = meta.credState === 'configured' ? configuredTtlMs : LIFECYCLE_TTL_UNCONFIGURED_MS
    const lastActivityMs = meta.lastActivityAt.getTime()
    if (now - lastActivityMs > ttlMs) {
      // Only terminate idle setup daemons aggressively; preserve pre-D9
      // behavior of unlink-only for configured daemons past TTL.
      if (meta.credState === 'unconfigured') {
        self.terminateDaemon(meta.pid)
      }
      try {
        unlinkSync(full)
        removed += 1
      } catch {
        /* ignore */
      }
    }
  }
  return removed
}

/**
 * Write the 4-line lock payload (pid, port, token, ISO timestamp) padded
 * to 512 bytes. Used by `runLocalServer` after the OS file lock is
 * acquired. Continues to write 4-line for backward compat — D9 sweep
 * treats 4-line as `credState='configured'` so behavior is equivalent.
 *
 * Returns the absolute path to the lock file.
 */
export function writeLockFile(serverName: string, port: number, token: string, root?: string): string {
  const dir = locksDir(root)
  const path = join(dir, `${serverName}-${port}.lock`)
  const payload = `${process.pid}\n${port}\n${token}\n${new Date().toISOString()}\n`
  writeFileSync(path, payload.padEnd(512, ' '), { encoding: 'utf-8', mode: 0o600 })
  return path
}
