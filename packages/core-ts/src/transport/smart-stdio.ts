import { spawn } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync, unlinkSync } from 'node:fs'
import * as os from 'node:os'
import { join } from 'node:path'
import * as readline from 'node:readline'

import { JWTIssuer } from '../oauth/jwt-issuer.js'

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
