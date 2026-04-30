import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as lockModule from '../../src/lifecycle/lock.js'
import * as browser from '../../src/relay/browser.js'
import * as session from '../../src/relay/session.js'
import { buildOpenRelayHandler, registerOpenRelayTool } from '../../src/relay/tool-helpers.js'
import * as smartStdio from '../../src/transport/smart-stdio.js'

const SCHEMA = {
  server: 'demo',
  fields: [{ name: 'API_KEY', label: 'API Key', required: true, secret: true }]
}

let tmpDir: string

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'mcp-core-tool-helpers-'))
  vi.restoreAllMocks()
})

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true })
})

describe('open_relay handler', () => {
  it('returns url when alive', async () => {
    vi.spyOn(smartStdio, 'daemonRelayUrl').mockReturnValue('http://127.0.0.1:55317/')
    vi.spyOn(smartStdio, 'daemonIsAlive').mockReturnValue(true)
    vi.spyOn(smartStdio, 'daemonCredState').mockReturnValue('configured')
    vi.spyOn(session, 'isSessionActive').mockReturnValue(false)
    const opened: string[] = []
    vi.spyOn(browser, 'tryOpenBrowser').mockImplementation(async (u: string) => {
      opened.push(u)
      return true
    })

    const handler = buildOpenRelayHandler('demo', SCHEMA)
    const result = await handler()

    expect(result.url).toBe('http://127.0.0.1:55317/')
    expect(result.browserOpened).toBe(true)
    expect(result.status).toBe('configured')
    expect(opened).toEqual(['http://127.0.0.1:55317/'])
  })

  it('session active', async () => {
    vi.spyOn(smartStdio, 'daemonRelayUrl').mockReturnValue('http://127.0.0.1:55317/')
    vi.spyOn(smartStdio, 'daemonIsAlive').mockReturnValue(true)
    vi.spyOn(smartStdio, 'daemonCredState').mockReturnValue('configured')
    vi.spyOn(session, 'isSessionActive').mockReturnValue(true)
    vi.spyOn(browser, 'tryOpenBrowser').mockResolvedValue(false)

    const handler = buildOpenRelayHandler('demo', SCHEMA)
    const result = await handler()

    expect(result.status).toBe('session_active')
    expect(result.browserOpened).toBe(false)
  })

  it('respawns when dead', async () => {
    let alive = false
    vi.spyOn(smartStdio, 'daemonIsAlive').mockImplementation(() => alive)
    vi.spyOn(smartStdio, 'daemonRespawn').mockImplementation(() => {
      alive = true
      return 'http://127.0.0.1:55320/'
    })
    vi.spyOn(smartStdio, 'daemonCredState').mockReturnValue('unconfigured')
    vi.spyOn(session, 'isSessionActive').mockReturnValue(false)
    vi.spyOn(browser, 'tryOpenBrowser').mockResolvedValue(true)

    const handler = buildOpenRelayHandler('demo', SCHEMA)
    const result = await handler()

    expect(result.url).toBe('http://127.0.0.1:55320/')
    expect(result.status).toBe('unconfigured')
    expect(alive).toBe(true)
  })
})

describe('registerOpenRelayTool', () => {
  it('registers config__open_relay tool on the mcp instance', () => {
    const calls: Array<{ name: string; description?: string }> = []
    const mcp = {
      tool(config: { name: string; description?: string }, _handler: () => Promise<unknown>) {
        calls.push(config)
      }
    }

    registerOpenRelayTool(mcp, 'demo', SCHEMA)

    expect(calls).toHaveLength(1)
    expect(calls[0].name).toBe('config__open_relay')
    expect(calls[0].description).toContain('demo')
  })
})

describe('daemonRelayUrl regression', () => {
  it('returns root URL not /setup?token= (daemon local_oauth_app registers /authorize not /setup)', () => {
    // Regression: legacy URL shape /setup?token=<jwt> 404'd in daemon mode (2026-04-30 Test B).
    // Daemon's local_oauth_app 302-redirects / → /authorize?... with fresh PKCE.
    vi.spyOn(lockModule, 'lockDir').mockReturnValue(tmpDir)
    const ts = new Date().toISOString()
    writeFileSync(join(tmpDir, 'test-server-12345.lock'), `12345\n55432\nstest-jwt-token\n${ts}\nconfigured\n${ts}\n`)

    const url = smartStdio.daemonRelayUrl('test-server')

    expect(url).not.toContain('/setup?token=')
    expect(url).toBe('http://127.0.0.1:55432/')
  })
})
