import { spawn } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync, unlinkSync } from 'node:fs'
import * as os from 'node:os'
import { join } from 'node:path'
import * as readline from 'node:readline'

import { isAlive, lockDir, parseLock } from '../lifecycle/lock.js'
import { JWTIssuer } from '../oauth/jwt-issuer.js'

/**
 * Return the relay form URL for the alive daemon of `serverName`.
 *
 * Walks the per-user lock directory, parses the first `<server>-*.lock`
 * that contains valid 4/5/6-line metadata, and constructs
 * `http://127.0.0.1:<port>/setup?token=<jwt>` so a Bridge can render a
 * user-facing setup link without going through the OAuth handshake.
 *
 * Throws when no parseable lock file exists for the server. Callers that
 * prefer a soft signal should call `daemonIsAlive` first.
 */
export function daemonRelayUrl(serverName: string): string {
  const dir = lockDir()
  if (!existsSync(dir)) throw new Error(`no alive daemon for ${serverName}`)
  for (const filename of readdirSync(dir)) {
    if (!filename.startsWith(`${serverName}-`) || !filename.endsWith('.lock')) continue
    try {
      const meta = parseLock(readFileSync(join(dir, filename), 'utf-8'))
      return `http://127.0.0.1:${meta.port}/setup?token=${meta.token}`
    } catch {
      // Skip unparseable lock files; try the next match.
    }
  }
  throw new Error(`no alive daemon for ${serverName}`)
}

/**
 * Return `true` when at least one parseable lock file for `serverName`
 * references a process the OS reports as alive. Used by the Bridge when
 * deciding whether `need_setup` envelopes should bridge to a live daemon
 * or trigger an auto-respawn.
 */
export function daemonIsAlive(serverName: string): boolean {
  const dir = lockDir()
  if (!existsSync(dir)) return false
  for (const filename of readdirSync(dir)) {
    if (!filename.startsWith(`${serverName}-`) || !filename.endsWith('.lock')) continue
    try {
      const meta = parseLock(readFileSync(join(dir, filename), 'utf-8'))
      if (isAlive(meta)) return true
    } catch {
      // Skip unparseable lock files; try the next match.
    }
  }
  return false
}

/**
 * Return the latest known `credState` for `serverName`. Reads the first
 * parseable lock file and returns its 5th line. Returns `"unconfigured"`
 * if no lock exists, so callers can branch safely on a single string
 * without nullable handling.
 */
export function daemonCredState(serverName: string): string {
  const dir = lockDir()
  if (!existsSync(dir)) return 'unconfigured'
  for (const filename of readdirSync(dir)) {
    if (!filename.startsWith(`${serverName}-`) || !filename.endsWith('.lock')) continue
    try {
      const meta = parseLock(readFileSync(join(dir, filename), 'utf-8'))
      return meta.credState
    } catch {
      // Skip unparseable lock files; try the next match.
    }
  }
  return 'unconfigured'
}

/**
 * Bridge auto-respawn (D8, Task 1.12).
 *
 * When a tool call fails because the daemon backing a transparent bridge
 * has died, the Bridge spawns a fresh daemon and retries -- but only once
 * per `tool_call_id`, so a pathological caller can't infinite-loop the
 * spawn path. ``BridgeAutoRespawn`` tracks the per-call cap; the helper
 * functions below perform the actual spawn + wait-ready dance.
 */
export const MAX_RESPAWN_PER_CALL_ID = 1
const RESPAWN_TRACK_TTL_MS = 5 * 60_000

/**
 * Per-bridge tracker capping respawn attempts per `tool_call_id`.
 *
 * A bridge instance keeps one of these for the lifetime of an MCP session.
 * Each unique id is allowed exactly `MAX_RESPAWN_PER_CALL_ID` respawn
 * attempt; subsequent attempts within `RESPAWN_TRACK_TTL_MS` are rejected
 * so a buggy caller can't spawn-storm the daemon. Entries older than the
 * TTL are dropped on read so the table doesn't grow without bound.
 */
export class BridgeAutoRespawn {
  private respawned = new Map<string, number>()

  canRespawn(callId: string): boolean {
    const ts = this.respawned.get(callId)
    if (ts === undefined) return true
    if (Date.now() - ts > RESPAWN_TRACK_TTL_MS) {
      this.respawned.delete(callId)
      return true
    }
    return false
  }

  markRespawned(callId: string): void {
    this.respawned.set(callId, Date.now())
  }
}

/**
 * Spawn `uvx <serverName>` detached from the parent process group.
 *
 * Production wiring intentionally minimal: the daemon publishes its lock
 * file as part of normal startup, so callers poll `daemonIsAlive` /
 * `daemonRelayUrl` to discover it. Tests stub this via `vi.spyOn` so the
 * suite never spawns real subprocesses.
 */
function spawnDaemonDetached(serverName: string): void {
  const child = spawn('uvx', [serverName], {
    detached: true,
    stdio: 'ignore',
    windowsHide: true
  })
  child.unref()
}

/**
 * Poll `daemonIsAlive` until alive or `timeoutMs` elapses. Mirrors
 * the core-py `_wait_daemon_ready` helper.
 */
async function waitDaemonReady(serverName: string, timeoutMs = 60_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (daemonIsAlive(serverName)) return true
    await new Promise((r) => setTimeout(r, 500))
  }
  return false
}

/**
 * Async respawn entry point. Production code should prefer this -- it
 * waits for the daemon to come back up before resolving with the relay URL.
 */
export async function daemonRespawnAsync(serverName: string): Promise<string> {
  if (daemonIsAlive(serverName)) return daemonRelayUrl(serverName)
  spawnDaemonDetached(serverName)
  if (!(await waitDaemonReady(serverName))) {
    throw new Error(`daemon respawn timeout for ${serverName}`)
  }
  return daemonRelayUrl(serverName)
}

/**
 * Synchronous respawn for callers that match the core-py signature.
 *
 * If a daemon is already alive we return its URL immediately. Otherwise we
 * fire-and-forget the spawn and return an empty string -- the caller is
 * expected to poll via `daemonIsAlive` / `daemonRelayUrl` (or use
 * `daemonRespawnAsync` for the awaitable flow).
 */
export function daemonRespawn(serverName: string): string {
  if (daemonIsAlive(serverName)) return daemonRelayUrl(serverName)
  spawnDaemonDetached(serverName)
  return ''
}

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

      const isAlive = await checkHealth(port)
      if (isAlive) {
        return { port, token }
      } else {
        try {
          unlinkSync(lockPath)
        } catch {}
      }
    } catch {}
  }
  return null
}

function parseSseMessages(text: string): string[] {
  const messages: string[] = []
  const lines = text.split('\n')
  let currentEvent = 'message'
  let dataLines: string[] = []

  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, '')
    if (line.startsWith('event:')) {
      if (dataLines.length > 0 && currentEvent === 'message') {
        messages.push(dataLines.join('\n'))
      }
      currentEvent = line.slice(6).trim()
      dataLines = []
    } else if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).trim())
    } else if (line === '') {
      if (dataLines.length > 0 && currentEvent === 'message') {
        messages.push(dataLines.join('\n'))
      }
      currentEvent = 'message'
      dataLines = []
    }
  }
  if (dataLines.length > 0 && currentEvent === 'message') {
    messages.push(dataLines.join('\n'))
  }
  return messages
}

class SseParser {
  private buffer = ''
  private currentEvent: { event?: string; dataLines: string[] } = { dataLines: [] }
  private firstEventResolve!: (result: { type: string; data: string }) => void
  private firstEventPromise: Promise<{ type: string; data: string }>
  private messageHandlers: Array<(data: string) => void> = []
  private messageQueue: string[] = []
  private firstEventReceived = false

  constructor() {
    this.firstEventPromise = new Promise((resolve) => {
      this.firstEventResolve = resolve
    })
  }

  feed(chunk: string) {
    this.buffer += chunk
    const lines = this.buffer.split('\n')
    this.buffer = lines.pop() || ''

    for (const rawLine of lines) {
      const line = rawLine.replace(/\r$/, '')
      if (line.startsWith('event:')) {
        this.currentEvent.event = line.slice(6).trim()
      } else if (line.startsWith('data:')) {
        this.currentEvent.dataLines.push(line.slice(5).trim())
      } else if (line === '') {
        this.dispatchEvent()
        this.currentEvent = { dataLines: [] }
      }
    }
  }

  private dispatchEvent() {
    const data = this.currentEvent.dataLines.join('\n')
    const eventName = this.currentEvent.event || 'message'

    if (!this.firstEventReceived && data) {
      this.firstEventReceived = true
      this.firstEventResolve({ type: eventName, data })
    }

    if (eventName === 'message' && data) {
      this.messageQueue.push(data)
      this.flushMessages()
    }
  }

  private flushMessages() {
    while (this.messageQueue.length > 0 && this.messageHandlers.length > 0) {
      const data = this.messageQueue.shift()!
      for (const handler of this.messageHandlers) {
        handler(data)
      }
    }
  }

  waitForFirstEvent(): Promise<{ type: string; data: string }> {
    return this.firstEventPromise
  }

  onMessage(handler: (data: string) => void) {
    this.messageHandlers.push(handler)
    this.flushMessages()
  }
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

  const url = `http://127.0.0.1:${daemon.port}/mcp`
  process.stderr.write(`[stdio-proxy] Connected to daemon at ${url}\n`)

  let authToken = daemon.token
  if (!authToken) {
    const issuer = new JWTIssuer(serverName)
    await issuer.init()
    authToken = await issuer.issueAccessToken('stdio-proxy', 365 * 24 * 3600)
    process.stderr.write(`[stdio-proxy] Lock token missing; generated proxy token for '${serverName}'.\n`)
  }

  const rl = readline.createInterface({
    input: process.stdin,
    terminal: false
  })

  const postHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream'
  }

  if (authToken) {
    postHeaders['Authorization'] = `Bearer ${authToken}`
  }

  let endpointUrl: string | null = null
  let isStateless = false
  let modeDetermined = false
  let activeSseBody: ReadableStream<Uint8Array> | null = null

  try {
    for await (const line of rl) {
      if (!line.trim()) continue

      if (!modeDetermined) {
        const res = await fetch(url, {
          method: 'POST',
          headers: postHeaders,
          body: line + '\n'
        })

        if (!res.ok) {
          process.stderr.write(`[stdio-proxy] HTTP error: ${res.status} ${res.statusText}\n`)
          return 2
        }

        const contentType = res.headers.get('content-type') || ''
        const isSse = contentType.includes('text/event-stream')

        if (!isSse) {
          const bodyText = await res.text()
          process.stdout.write(bodyText)
          if (!bodyText.endsWith('\n')) {
            process.stdout.write('\n')
          }
          isStateless = true
          modeDetermined = true
          process.stderr.write(`[stdio-proxy] Stateless mode detected (plain JSON response)\n`)
          continue
        }

        if (!res.body) {
          process.stderr.write(`[stdio-proxy] No response body from SSE connection\n`)
          return 2
        }

        // Streamable HTTP (newer MCP transport spec) sends the session id as
        // an HTTP response header on the initialize response. Older HTTP+SSE
        // transport instead encodes the session id inside an "endpoint" SSE
        // event. Detect Streamable HTTP first; the daemon returns 400 on
        // subsequent POSTs without `Mcp-Session-Id`, so silently treating
        // sessionful Streamable HTTP as stateless leaves the proxy stuck.
        const sessionIdHeader = res.headers.get('mcp-session-id')
        if (sessionIdHeader) {
          postHeaders['Mcp-Session-Id'] = sessionIdHeader
          endpointUrl = url
          modeDetermined = true
          process.stderr.write(`[stdio-proxy] Streamable HTTP session: ${sessionIdHeader}\n`)

          activeSseBody = res.body
          const parser = new SseParser()
          const reader = res.body.getReader()
          const decoder = new TextDecoder()

          parser.onMessage((data) => {
            process.stdout.write(data)
            if (!data.endsWith('\n')) {
              process.stdout.write('\n')
            }
          })

          const readSsePromise = (async () => {
            try {
              while (true) {
                const { done, value } = await reader.read()
                if (done) break
                parser.feed(decoder.decode(value, { stream: true }))
              }
            } catch (e: any) {
              process.stderr.write(`[stdio-proxy] SSE error: ${e}\n`)
            }
          })()

          // Drain the initialize-response SSE body before reading the next
          // stdin line, so we don't lose the response or starve the client.
          try {
            await readSsePromise
          } catch {}
          activeSseBody = null
          continue
        }

        activeSseBody = res.body
        const parser = new SseParser()
        const reader = res.body.getReader()
        const decoder = new TextDecoder()

        const readSsePromise = (async () => {
          try {
            while (true) {
              const { done, value } = await reader.read()
              if (done) break
              parser.feed(decoder.decode(value, { stream: true }))
            }
          } catch (e: any) {
            process.stderr.write(`[stdio-proxy] SSE error: ${e}\n`)
          }
        })()

        const firstEvent = await parser.waitForFirstEvent()

        if (firstEvent.type === 'endpoint') {
          endpointUrl = new URL(firstEvent.data, url).href

          const sessionId = new URL(endpointUrl).searchParams.get('sessionId')
          if (sessionId) {
            postHeaders['MCP-Session-ID'] = sessionId
          }

          process.stderr.write(`[stdio-proxy] Session endpoint: ${endpointUrl}\n`)

          parser.onMessage((data) => {
            process.stdout.write(data)
            if (!data.endsWith('\n')) {
              process.stdout.write('\n')
            }
          })

          void readSsePromise
          modeDetermined = true
          continue
        } else {
          process.stdout.write(firstEvent.data)
          if (!firstEvent.data.endsWith('\n')) {
            process.stdout.write('\n')
          }
          isStateless = true
          modeDetermined = true
          process.stderr.write(`[stdio-proxy] Stateless mode detected (SSE message event)\n`)

          // Cancel the SSE body BEFORE awaiting the reader promise. Otherwise,
          // a daemon that keeps the SSE connection open (typical for stateless
          // streamable HTTP) will cause `readSsePromise` to never resolve,
          // hanging the readline loop and starving the stdio client. Cancelling
          // first signals `done=true` to the reader so the promise resolves.
          if (activeSseBody) {
            await activeSseBody.cancel().catch(() => {})
            activeSseBody = null
          }
          try {
            await readSsePromise
          } catch {}
          continue
        }
      }

      const targetUrl = isStateless ? url : endpointUrl!
      if (!isStateless && !endpointUrl) {
        process.stderr.write(`[stdio-proxy] Session endpoint not established.\n`)
        return 2
      }

      if (daemon?.token) {
        postHeaders['Authorization'] = `Bearer ${daemon.token}`
      }

      try {
        const res = await fetch(targetUrl, {
          method: 'POST',
          headers: postHeaders,
          body: line + '\n'
        })

        if (!res.ok) {
          process.stderr.write(`[stdio-proxy] HTTP error: ${res.status} ${res.statusText}\n`)
          return 2
        }

        const contentType = res.headers.get('content-type') || ''
        if (contentType.includes('text/event-stream')) {
          const bodyText = await res.text()
          const messages = parseSseMessages(bodyText)
          for (const msg of messages) {
            process.stdout.write(msg)
            if (!msg.endsWith('\n')) {
              process.stdout.write('\n')
            }
          }
        } else {
          const bodyText = await res.text()
          process.stdout.write(bodyText)
          if (!bodyText.endsWith('\n')) {
            process.stdout.write('\n')
          }
        }
      } catch (e: any) {
        process.stderr.write(`[stdio-proxy] Daemon '${serverName}' died unexpectedly.\n`)
        return 2
      }
    }

    return 0
  } catch (e: any) {
    process.stderr.write(`[stdio-proxy] Connection failed: ${e}\n`)
    return 2
  } finally {
    if (activeSseBody) {
      await activeSseBody.cancel().catch(() => {})
    }
    rl.close()
  }
}
