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

import { existsSync } from 'node:fs'
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

// Self-namespace import lets ``vi.spyOn(cacheModule, 'cacheDir' | 'atomicWrite')``
// intercept internal calls (ESM bindings make plain references unmockable).
import * as self from './cache.js'

export function cacheDir(): string {
  return join(homedir(), '.config', 'mcp', 'cache')
}

export function cacheFilename(serverName: string, port: number, srvVersion: string, coreVersion: string): string {
  return `${serverName}-${port}-${srvVersion}-${coreVersion}.tools.json`
}

export async function atomicWrite(path: string, content: string): Promise<void> {
  const dir = dirname(path)
  if (dir && !existsSync(dir)) await mkdir(dir, { recursive: true })
  const tmp = `${path}.tmp`
  await writeFile(tmp, content, { encoding: 'utf-8' })
  if (process.platform !== 'win32') {
    try {
      await chmod(tmp, 0o600)
    } catch {
      /* ignore */
    }
  }
  await rename(tmp, path)
}

export async function persistToolsCache(
  serverName: string,
  port: number,
  srvVersion: string,
  coreVersion: string,
  tools: unknown[]
): Promise<void> {
  const path = join(self.cacheDir(), cacheFilename(serverName, port, srvVersion, coreVersion))
  const payload = JSON.stringify({ tools, srvVersion, coreVersion })
  try {
    await self.atomicWrite(path, payload)
  } catch (err) {
    // Suppress per D10 — log only.
    console.debug('Failed to persist capabilities cache for %s: %s', serverName, err)
  }
}

export async function loadToolsCache(
  serverName: string,
  port: number,
  srvVersion: string,
  coreVersion: string
): Promise<unknown[] | null> {
  const path = join(self.cacheDir(), cacheFilename(serverName, port, srvVersion, coreVersion))
  try {
    const data = await readFile(path, 'utf-8')
    const payload = JSON.parse(data)
    if (payload.srvVersion !== srvVersion || payload.coreVersion !== coreVersion) return null
    return Array.isArray(payload.tools) ? payload.tools : null
  } catch {
    return null
  }
}
