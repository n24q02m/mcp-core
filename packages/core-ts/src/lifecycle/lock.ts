/**
 * Lock-file lifecycle helpers for stale lock detection.
 *
 * The lock file written by `runLocalServer` contains 4 lines of metadata:
 *
 * ```
 * {pid}
 * {port}
 * {token}
 * {created_at_iso8601_utc}
 * ```
 *
 * Stale locks are detected when *any* of:
 *  - file has legacy 3-line format (no timestamp) → migrate by deletion
 *  - timestamp older than `ttlHours` (default 24)
 *  - writing PID does not exist on this host
 *
 * TypeScript port of core-py's `mcp_core.lifecycle.lock`. Behaviour and TTL
 * constant are kept identical for cross-language parity.
 */

import { existsSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export const DEFAULT_LOCK_TTL_HOURS = 24

export interface LockMetadata {
  pid: number
  port: number
  token: string
  createdAt: Date
}

export function locksDir(root?: string): string {
  return root ?? join(homedir(), '.config', 'mcp', 'locks')
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
  if (lines.length < 4) return null

  const pidStr = lines[0]?.trim()
  const portStr = lines[1]?.trim()
  const token = lines[2]?.trim() ?? ''
  const tsStr = lines[3]?.trim()

  if (pidStr === undefined || portStr === undefined || tsStr === undefined) return null
  const pid = Number(pidStr)
  const port = Number(portStr)
  if (!Number.isInteger(pid) || !Number.isInteger(port)) return null
  const createdAt = new Date(tsStr)
  if (Number.isNaN(createdAt.getTime())) return null

  return { pid, port, token, createdAt }
}

export function isLockExpired(path: string, ttlHours: number = DEFAULT_LOCK_TTL_HOURS): boolean {
  const md = parseLockMetadata(path)
  if (md === null) return true
  const ageMs = Date.now() - md.createdAt.getTime()
  return ageMs > ttlHours * 3600 * 1000
}

/**
 * Cross-platform PID liveness check via `process.kill(pid, 0)`. Best-effort.
 * Returns false on EPERM (different-user processes) so sweep does not steal
 * locks owned by other users.
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
 * Refresh `createdAt` of an existing 4-line lock file. Silent no-op on
 * legacy / malformed files so callers don't need try/except.
 *
 * Padded to 512 bytes so on-disk size stays stable while a Windows
 * byte-range lock is held past the metadata region (parity with core-py).
 */
export function refreshLockTimestamp(path: string): void {
  const md = parseLockMetadata(path)
  if (md === null) return
  const payload = `${md.pid}\n${md.port}\n${md.token}\n${new Date().toISOString()}\n`
  try {
    writeFileSync(path, payload.padEnd(512, ' '), { encoding: 'utf-8' })
  } catch {
    // Best-effort
  }
}

/**
 * Remove stale lock files for `serverName`. Returns count removed.
 *
 * Called by `runLocalServer` at daemon startup before writing its own lock,
 * preventing pile-up of dozens of `<server>-<port>.lock` files when daemons
 * exit abnormally (Windows OOM, taskkill, signal).
 */
export function sweepStaleLocks(serverName: string, ttlHours: number = DEFAULT_LOCK_TTL_HOURS, root?: string): number {
  const dir = locksDir(root)
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

  for (const entry of entries) {
    if (!entry.startsWith(prefix) || !entry.endsWith(suffix)) continue
    const full = join(dir, entry)
    const md = parseLockMetadata(full)
    if (md === null) {
      try {
        unlinkSync(full)
        removed += 1
      } catch {
        // Best-effort
      }
      continue
    }
    if (isLockExpired(full, ttlHours) || !isPidAlive(md.pid)) {
      try {
        unlinkSync(full)
        removed += 1
      } catch {
        // Best-effort
      }
    }
  }
  return removed
}

/**
 * Write the 4-line lock payload (pid, port, token, ISO timestamp) padded to
 * 512 bytes. Used by `runLocalServer` after the OS file lock is acquired.
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
