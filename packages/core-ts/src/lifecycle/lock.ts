/**
 * Lock-file lifecycle helpers for HTTP server mode.
 *
 * After the stdio-pure + http-multi-user split, lock files are used solely
 * by `runHttpServer` to prevent two HTTP servers binding the same port for
 * the same `serverName`. They are no longer used to discover or steer
 * daemon-bridge processes; per-credState TTLs and PID liveness checks have
 * been removed along with the daemon model.
 *
 * On-disk format (4 lines + trailing newline, padded to 512 bytes):
 *
 * ```
 * {pid}
 * {port}
 * {token}
 * {spawnedAt_iso8601_utc}
 * ```
 *
 * `sweepStaleLocks` removes lock files whose `spawnedAt` is older than the
 * configured TTL. There is no daemon to terminate — the HTTP server owns
 * its own lifecycle and exits when its parent process exits.
 *
 * TypeScript port of core-py's `mcp_core.lifecycle.lock`. Behaviour kept
 * identical for cross-language parity.
 */

import {
  closeSync,
  existsSync,
  fstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

// Self-import so `sweepStaleLocks` can resolve `lockDir` through the
// module namespace at call time. This makes
// `vi.spyOn(lockModule, 'lockDir').mockReturnValue(...)` actually
// intercept the helper from inside the sweep loop — without this
// indirection, the closure-captured local binding ignores spies and
// test mocks become silent no-ops.
import * as self from './lock.js'

export const DEFAULT_LOCK_TTL_HOURS = 24

/** Parsed lock metadata — shared by sweep and refresh helpers. */
export interface LockMetadata {
  pid: number
  port: number
  token: string
  spawnedAt: Date
}

export function locksDir(root?: string): string {
  return root ?? join(homedir(), '.config', 'mcp', 'locks')
}

/**
 * No-arg lock-dir resolver — sweep tests `vi.spyOn(lockModule, 'lockDir')`
 * to redirect into a temp directory without threading a `root` arg.
 */
export function lockDir(): string {
  return locksDir()
}

/** Internal helper: parse the textual lock payload into `LockMetadata`. */
function parseLockText(raw: string): LockMetadata | null {
  const lines = raw.replace(/\n+$/, '').split('\n')
  if (lines.length < 4) return null
  const pid = Number(lines[0])
  const port = Number(lines[1])
  if (!Number.isInteger(pid) || !Number.isInteger(port)) return null
  const token = lines[2]
  const spawnedAt = new Date(lines[3])
  if (Number.isNaN(spawnedAt.getTime())) return null
  return { pid, port, token, spawnedAt }
}

/**
 * Refresh `spawnedAt` of an existing lock file. Silent no-op on legacy /
 * malformed files so callers don't need try/except.
 *
 * Padded to 512 bytes so on-disk size stays stable while a Windows
 * byte-range lock is held past the metadata region (parity with core-py).
 */
export function refreshLockTimestamp(path: string): void {
  if (!existsSync(path)) return
  let raw: string
  try {
    raw = readFileSync(path, { encoding: 'utf-8' })
  } catch {
    return
  }
  const md = parseLockText(raw)
  if (md === null) return
  const now = new Date().toISOString()
  const payload = `${md.pid}\n${md.port}\n${md.token}\n${now}\n`
  try {
    writeFileSync(path, payload.padEnd(512, ' '), { encoding: 'utf-8' })
  } catch {
    // Best-effort
  }
}

/**
 * Remove stale lock files for `serverName`. Returns count removed.
 *
 * Called by `runHttpServer` at startup before writing its own lock,
 * preventing pile-up of dozens of `<server>-<port>.lock` files when HTTP
 * servers exit abnormally (Windows OOM, taskkill, signal).
 *
 * A lock is stale when:
 *  - file is unreadable or has malformed payload (legacy / corrupt)
 *  - `spawnedAt` is older than the TTL
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

  const filename = `${serverName}.lock`
  const now = Date.now()
  const ttlMs = (ttlHours ?? DEFAULT_LOCK_TTL_HOURS) * 3600 * 1000

  for (const entry of entries) {
    if (entry !== filename) continue
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
    const meta = parseLockText(raw)
    if (meta === null) {
      try {
        unlinkSync(full)
        removed += 1
      } catch {
        /* ignore */
      }
      continue
    }

    // Check PID liveness
    let isAlive = true
    try {
      process.kill(meta.pid, 0)
    } catch {
      isAlive = false
    }

    if (!isAlive || now - meta.spawnedAt.getTime() > ttlMs) {
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
 * Lifecycle lock guarding a single `serverName` HTTP server.
 * TypeScript implementation using O_EXCL for atomic creation.
 */
export class LifecycleLock {
  private _path: string
  private _fd: number | null = null

  constructor(
    _name: string,
    private _port: number,
    private _token: string,
    root?: string
  ) {
    const dir = locksDir(root)
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    this._path = join(dir, `${_name}.lock`)
  }

  get path(): string {
    return this._path
  }

  acquire(): void {
    try {
      // Use wx for atomic creation + exclusive access.
      this._fd = openSync(this._path, 'wx', 0o600)
    } catch (err: unknown) {
      const error = err as { code?: string }
      if (error.code === 'EEXIST') {
        // Check if process is still alive
        let existingRaw: string
        try {
          existingRaw = readFileSync(this._path, 'utf-8')
        } catch {
          // Raced with unlink, retry open once
          this._fd = openSync(this._path, 'wx', 0o600)
          return
        }

        const meta = parseLockText(existingRaw)
        if (meta) {
          let isAlive = true
          try {
            process.kill(meta.pid, 0)
          } catch (killErr: unknown) {
            const kError = killErr as { code?: string }
            if (kError.code === 'EPERM') {
              throw new Error(`LifecycleLock: another process holds ${this._path} (EPERM)`)
            }
            isAlive = false
          }

          if (isAlive) {
            throw new Error(`LifecycleLock: another process (PID ${meta.pid}) holds ${this._path}`)
          } else {
            // PID not alive, attempt to reclaim
            try {
              unlinkSync(this._path)
            } catch {
              /* ignore race */
            }
            this._fd = openSync(this._path, 'wx', 0o600)
          }
        } else {
          // Malformed, reclaim
          try {
            unlinkSync(this._path)
          } catch {
            /* ignore race */
          }
          this._fd = openSync(this._path, 'wx', 0o600)
        }
      } else {
        throw err
      }
    }

    if (this._fd !== null) {
      const payload = `${process.pid}\n${this._port}\n${this._token}\n${new Date().toISOString()}\n`
      writeFileSync(this._fd, payload.padEnd(512, ' '), { encoding: 'utf-8' })
    }
  }

  release(): void {
    if (this._fd !== null) {
      try {
        const fstat = fstatSync(this._fd)
        const dstat = statSync(this._path)
        if (fstat.ino === dstat.ino) {
          unlinkSync(this._path)
        }
      } catch {
        /* ignore */
      }
      closeSync(this._fd)
      this._fd = null
    }
  }
}

/**
 * Legacy helper for runHttpServer.
 * NOTE: Prefer using LifecycleLock class for robust holding.
 */
export function writeLockFile(serverName: string, port: number, token: string, root?: string): string {
  const dir = locksDir(root)
  const path = join(dir, `${serverName}.lock`)
  const payload = `${process.pid}\n${port}\n${token}\n${new Date().toISOString()}\n`
  writeFileSync(path, payload.padEnd(512, ' '), { encoding: 'utf-8', mode: 0o600 })
  return path
}
