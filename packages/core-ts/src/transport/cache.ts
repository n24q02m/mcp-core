/**
 * Tools-list cache with version-aware key (D10) — TS parity with core-py.
 *
 * Cache filename: ``<server>-<port>-<srvVersion>-<coreVersion>.tools.json``.
 * A mismatch on either ``srvVersion`` (the upstream MCP server's version) or
 * ``coreVersion`` (mcp-core itself) invalidates the cache, so an upgrade on
 * either side never serves a stale tool surface.
 *
 * ``persistToolsCache`` writes via ``.tmp`` + ``rename`` (Windows-safe) and
 * suppresses all filesystem errors with a debug log. This is the D10
 * root-cause fix for ``Failed to persist capabilities cache`` hard-failures
 * (crg #384).
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

// Self-namespace import lets ``vi.spyOn(cacheModule, 'cacheDir' | 'atomicWrite')``
// intercept internal calls (ESM bindings make plain references unmockable).
import * as self from './cache.js'

export function cacheDir(): string {
  return join(homedir(), '.config', 'mcp', 'cache')
}

export function cacheFilename(serverName: string, port: number, srvVersion: string, coreVersion: string): string {
  const safeName = serverName.replace(/[^a-zA-Z0-9.-]/g, '_').replace(/\.\./g, '__')
  const safeSrvVersion = srvVersion.replace(/[^a-zA-Z0-9.-]/g, '_').replace(/\.\./g, '__')
  const safeCoreVersion = coreVersion.replace(/[^a-zA-Z0-9.-]/g, '_').replace(/\.\./g, '__')
  return `${safeName}-${port}-${safeSrvVersion}-${safeCoreVersion}.tools.json`
}

export function atomicWrite(path: string, content: string): void {
  const dir = dirname(path)
  if (dir && !existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 })
  const tmp = `${path}.tmp`
  writeFileSync(tmp, content, { encoding: 'utf-8' })
  if (process.platform !== 'win32') {
    try {
      chmodSync(tmp, 0o600)
    } catch {
      /* ignore */
    }
  }
  renameSync(tmp, path)
}

export function persistToolsCache(
  serverName: string,
  port: number,
  srvVersion: string,
  coreVersion: string,
  tools: unknown[]
): void {
  const path = join(self.cacheDir(), cacheFilename(serverName, port, srvVersion, coreVersion))
  const payload = JSON.stringify({ tools, srv_version: srvVersion, core_version: coreVersion })
  try {
    self.atomicWrite(path, payload)
  } catch (err) {
    // Suppress per D10 — log only.
    console.debug('Failed to persist capabilities cache for %s: %s', serverName, err)
  }
}

export function loadToolsCache(
  serverName: string,
  port: number,
  srvVersion: string,
  coreVersion: string
): unknown[] | null {
  const path = join(self.cacheDir(), cacheFilename(serverName, port, srvVersion, coreVersion))
  if (!existsSync(path)) return null
  try {
    const payload = JSON.parse(readFileSync(path, 'utf-8'))
    if (payload.srv_version !== srvVersion || payload.core_version !== coreVersion) return null
    return Array.isArray(payload.tools) ? payload.tools : null
  } catch {
    return null
  }
}
