import { spawn } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync, unlinkSync } from 'node:fs'
import * as os from 'node:os'
import { join } from 'node:path'
import * as readline from 'node:readline'

export interface ActiveDaemon {
  port: number
  token: string
}

function getLocksDir(): string {
  return join(os.homedir(), '.config', 'mcp', 'locks')
}

async function checkHealth(port: number): Promise<boolean> {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/health`, {
      // Node 20+ supports AbortSignal.timeout
      signal: AbortSignal.timeout(1000)
    })
    return res.ok
  } catch {
    return false
  }
}

export async function getActiveDaemon(serverName: string): Promise<ActiveDaemon | null> {
  const locksDir = getLocksDir()
  if (!existsSync(locksDir)) return null

  const files = readdirSync(locksDir)
    .filter((f) => f.startsWith(`${serverName}-`) && f.endsWith('.lock'))
    .map((f) => join(locksDir, f))

  // Sort by mtime descending (newest first)
  files.sort((a, b) => {
    try {
      return statSync(b).mtimeMs - statSync(a).mtimeMs
    } catch {
      return 0
    }
  })

  for (const lockPath of files) {
    try {
      const content = readFileSync(lockPath, 'utf-8').trim()
      const lines = content.split('\n')
      if (lines.length < 2) continue
      const port = parseInt(lines[1].trim(), 10)
      const token = lines.length > 2 ? lines[2].trim() : ''

      // Liveness probe via HTTP
      const isAlive = await checkHealth(port)
      if (isAlive) {
        return { port, token }
      } else {
        // Stale lock, clean it up
        try {
          unlinkSync(lockPath)
        } catch {}
      }
    } catch {
      // Ignore read errors
    }
  }
  return null
}

export async function runSmartStdioProxy(
  serverName: string,
  daemonCmd: string[],
  options: { startupTimeout?: number; env?: Record<string, string | undefined> } = {}
): Promise<number> {
  const startupTimeout = options.startupTimeout ?? 15000
  let daemon = await getActiveDaemon(serverName)

  if (!daemon) {
    process.stderr.write(`[stdio-proxy] No active daemon for '${serverName}'. Spawning...\n`)

    const [cmd, ...args] = daemonCmd
    const child = spawn(cmd, args, {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
      env: options.env ? { ...process.env, ...options.env } : process.env
    })
    child.unref()

    const deadline = Date.now() + startupTimeout
    while (Date.now() < deadline) {
      daemon = await getActiveDaemon(serverName)
      if (daemon) break
      await new Promise((r) => setTimeout(r, 150))
    }

    if (!daemon) {
      process.stderr.write(
        `[stdio-proxy] Daemon for '${serverName}' did not start within ${Math.round(startupTimeout / 1000)}s. Aborting.\n`
      )
      return 1
    }
  }

  process.stderr.write(`[stdio-proxy] Connected to daemon at http://127.0.0.1:${daemon.port}/mcp\n`)

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream'
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
  })

  for await (const line of rl) {
    if (!line.trim()) continue

    // Refresh token header if needed
    if (daemon?.token) {
      headers['Authorization'] = `Bearer ${daemon.token}`
    }

    try {
      const res = await fetch(`http://127.0.0.1:${daemon.port}/mcp`, {
        method: 'POST',
        headers,
        body: line + '\n'
      })
      const text = await res.text()
      process.stdout.write(text)
      if (!text.endsWith('\n')) {
        process.stdout.write('\n')
      }
    } catch (e: any) {
      // Re-probe on connection error (daemon might have restarted)
      const newDaemon = await getActiveDaemon(serverName)
      if (!newDaemon) {
        process.stderr.write(`[stdio-proxy] Daemon '${serverName}' died unexpectedly.\n`)
        return 2
      }
      daemon = newDaemon
    }
  }

  return 0
}
