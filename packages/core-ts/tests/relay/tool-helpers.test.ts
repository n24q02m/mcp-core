import { beforeEach, describe, expect, it, vi } from 'vitest'
import * as browser from '../../src/relay/browser.js'
import * as session from '../../src/relay/session.js'
import { buildOpenRelayHandler, registerOpenRelayTool } from '../../src/relay/tool-helpers.js'
import * as smartStdio from '../../src/transport/smart-stdio.js'

const SCHEMA = {
  server: 'demo',
  fields: [{ name: 'API_KEY', label: 'API Key', required: true, secret: true }]
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('open_relay handler', () => {
  it('returns url when alive', async () => {
    vi.spyOn(smartStdio, 'daemonRelayUrl').mockReturnValue('http://127.0.0.1:55317/setup?token=abc')
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

    expect(result.url).toBe('http://127.0.0.1:55317/setup?token=abc')
    expect(result.browserOpened).toBe(true)
    expect(result.status).toBe('configured')
    expect(opened).toEqual(['http://127.0.0.1:55317/setup?token=abc'])
  })

  it('session active', async () => {
    vi.spyOn(smartStdio, 'daemonRelayUrl').mockReturnValue('http://127.0.0.1:55317/setup')
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
      return 'http://127.0.0.1:55320/setup?token=new'
    })
    vi.spyOn(smartStdio, 'daemonCredState').mockReturnValue('unconfigured')
    vi.spyOn(session, 'isSessionActive').mockReturnValue(false)
    vi.spyOn(browser, 'tryOpenBrowser').mockResolvedValue(true)

    const handler = buildOpenRelayHandler('demo', SCHEMA)
    const result = await handler()

    expect(result.url).toBe('http://127.0.0.1:55320/setup?token=new')
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
