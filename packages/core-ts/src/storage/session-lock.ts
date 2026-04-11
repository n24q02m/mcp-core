/**
 * File-based session lock to prevent duplicate relay sessions.
 *
 * When multiple MCP server processes start simultaneously (common in Claude Code),
 * this lock prevents each from creating a separate relay session (rate limit:
 * max 10 sessions/IP/10min).
 *
 * Lock file location: <config_dir>/mcp/relay-session-<server>.lock
 */

import { existsSync } from 'node:fs'
import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import envPaths from 'env-paths'

const paths = envPaths('mcp', { suffix: '' })
const DEFAULT_LOCK_DIR = paths.config

const DEFAULT_MAX_AGE_MS = 600_000

// Allow overriding lock directory for testing
let lockDirOverride: string | null = null

export function setLockDir(path: string | null): void {
  lockDirOverride = path
}

function getLockDir(): string {
  return lockDirOverride ?? DEFAULT_LOCK_DIR
}

function lockPath(serverName: string): string {
  return join(getLockDir(), `relay-session-${serverName}.lock`)
}

export interface SessionInfo {
  sessionId: string
  relayUrl: string
  createdAt: number // Date.now()
}

interface SessionInfoJson {
  session_id: string
  relay_url: string
  created_at: number
}

export async function acquireSessionLock(
  serverName: string,
  maxAgeMs = DEFAULT_MAX_AGE_MS
): Promise<SessionInfo | null> {
  const path = lockPath(serverName)
  try {
    if (!existsSync(path)) {
      return null
    }

    const raw = await readFile(path, 'utf-8')
    const data = JSON.parse(raw) as SessionInfoJson

    // Validate required fields
    if (
      typeof data.session_id !== 'string' ||
      typeof data.relay_url !== 'string' ||
      typeof data.created_at !== 'number'
    ) {
      await releaseSessionLock(serverName)
      return null
    }

    const info: SessionInfo = {
      sessionId: data.session_id,
      relayUrl: data.relay_url,
      createdAt: data.created_at
    }

    const age = Date.now() - info.createdAt
    if (age > maxAgeMs) {
      // Expired lock: clean up and return null
      await releaseSessionLock(serverName)
      return null
    }

    return info
  } catch {
    // Corrupt or unreadable lock file: clean up and return null
    try {
      await releaseSessionLock(serverName)
    } catch {
      /* ignore cleanup errors */
    }
    return null
  }
}

export async function writeSessionLock(serverName: string, info: SessionInfo): Promise<void> {
  const path = lockPath(serverName)
  const dir = dirname(path)
  if (!existsSync(dir)) {
    await mkdir(dir, { recursive: true })
  }

  const data: SessionInfoJson = {
    session_id: info.sessionId,
    relay_url: info.relayUrl,
    created_at: info.createdAt
  }

  // Write atomically via temp file + rename
  const tmpPath = `${path}.tmp`
  await writeFile(tmpPath, JSON.stringify(data), 'utf-8')
  await rename(tmpPath, path)
}

export async function releaseSessionLock(serverName: string): Promise<void> {
  const path = lockPath(serverName)
  try {
    if (existsSync(path)) {
      await unlink(path)
    }
  } catch {
    /* ignore errors during cleanup */
  }
}
