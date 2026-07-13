import type { ClientCapabilities, ElicitResult } from '@modelcontextprotocol/sdk/types.js'
import { describe, expect, it, type Mock, vi } from 'vitest'
import { tryOpenBrowser } from '../../src/relay/browser.js'
import {
  buildOpenRelayHandler,
  type ElicitationServer,
  registerOpenRelayTool,
  type ToolRegistrar
} from '../../src/relay/tool-helpers.js'

vi.mock('../../src/relay/browser.js', () => ({
  tryOpenBrowser: vi.fn().mockResolvedValue(true)
}))

function makeElicitation(hasUrlCap: boolean, action: 'accept' | 'decline' | 'cancel' = 'accept'): ElicitationServer {
  const capabilities = (hasUrlCap ? { elicitation: { url: {} } } : { elicitation: { form: {} } }) as ClientCapabilities
  return {
    getClientCapabilities: vi.fn(() => capabilities),
    elicitInput: vi.fn(async () => ({ action }) as ElicitResult)
  }
}

describe('buildOpenRelayHandler -- HTTP mode', () => {
  it('returns the server-provided authorize URL', async () => {
    const handler = buildOpenRelayHandler({
      serverName: 'test-server',
      publicUrl: 'http://127.0.0.1:8080'
    })
    const result = await handler()
    expect(result.url).toBe('http://127.0.0.1:8080/authorize')
    expect(result.status).toBe('unconfigured')
    expect(result.browserOpened).toBe(true)
    expect(result.elicitation).toBeUndefined()
    expect(tryOpenBrowser).toHaveBeenCalledWith('http://127.0.0.1:8080/authorize')
  })

  it('strips trailing slash in publicUrl', async () => {
    const handler = buildOpenRelayHandler({
      serverName: 'test-server',
      publicUrl: 'http://127.0.0.1:8080/'
    })
    const result = await handler()
    expect(result.url).toBe('http://127.0.0.1:8080/authorize')
  })

  it('returns stdio_unsupported in stdio mode (null publicUrl)', async () => {
    const handler = buildOpenRelayHandler({ serverName: 'test-server', publicUrl: null })
    const result = await handler()
    expect(result.status).toBe('stdio_unsupported')
    expect(result.url).toBe('')
    expect(result.browserOpened).toBe(false)
  })

  it('browser open failure still returns url', async () => {
    vi.mocked(tryOpenBrowser).mockResolvedValueOnce(false)
    const handler = buildOpenRelayHandler({
      serverName: 'test-server',
      publicUrl: 'http://127.0.0.1:8080'
    })
    const result = await handler()
    expect(result.url).toBe('http://127.0.0.1:8080/authorize')
    expect(result.browserOpened).toBe(false)
  })
})

describe('buildOpenRelayHandler -- URL elicitation', () => {
  it('elicits when the client declares url capability', async () => {
    vi.mocked(tryOpenBrowser).mockClear()
    const elicitation = makeElicitation(true, 'accept')
    const handler = buildOpenRelayHandler({
      serverName: 'test-server',
      publicUrl: 'http://127.0.0.1:8080',
      elicitation
    })
    const result = await handler()

    expect(elicitation.elicitInput).toHaveBeenCalledTimes(1)
    const params = (elicitation.elicitInput as Mock).mock.calls[0][0]
    expect(params.mode).toBe('url')
    expect(params.url).toBe('http://127.0.0.1:8080/authorize')
    expect(params.message).toContain('test-server')
    expect(typeof params.elicitationId).toBe('string')
    expect(params.elicitationId.length).toBeGreaterThan(0)
    // The client opens the URL in URL-mode; the server must NOT open a browser.
    expect(tryOpenBrowser).not.toHaveBeenCalled()
    expect(result).toEqual({
      url: 'http://127.0.0.1:8080/authorize',
      browserOpened: false,
      status: 'unconfigured',
      elicitation: 'accepted'
    })
  })

  it('maps declined action', async () => {
    const elicitation = makeElicitation(true, 'decline')
    const handler = buildOpenRelayHandler({
      serverName: 'test-server',
      publicUrl: 'http://127.0.0.1:8080',
      elicitation
    })
    const result = await handler()
    expect(result.elicitation).toBe('declined')
  })

  it('maps cancelled action', async () => {
    const elicitation = makeElicitation(true, 'cancel')
    const handler = buildOpenRelayHandler({
      serverName: 'test-server',
      publicUrl: 'http://127.0.0.1:8080',
      elicitation
    })
    const result = await handler()
    expect(result.elicitation).toBe('cancelled')
  })

  it('strips trailing slash in the elicited url', async () => {
    const elicitation = makeElicitation(true)
    const handler = buildOpenRelayHandler({
      serverName: 'test-server',
      publicUrl: 'http://127.0.0.1:8080/',
      elicitation
    })
    await handler()
    const params = (elicitation.elicitInput as Mock).mock.calls[0][0]
    expect(params.url).toBe('http://127.0.0.1:8080/authorize')
  })

  it('falls back to browser-open when the client lacks url capability', async () => {
    vi.mocked(tryOpenBrowser).mockClear()
    vi.mocked(tryOpenBrowser).mockResolvedValueOnce(true)
    const elicitation = makeElicitation(false)
    const handler = buildOpenRelayHandler({
      serverName: 'test-server',
      publicUrl: 'http://127.0.0.1:8080',
      elicitation
    })
    const result = await handler()

    expect(elicitation.elicitInput).not.toHaveBeenCalled()
    expect(tryOpenBrowser).toHaveBeenCalledWith('http://127.0.0.1:8080/authorize')
    // Fallback invariant: EXACT legacy dict, no `elicitation` key.
    expect(result).toEqual({
      url: 'http://127.0.0.1:8080/authorize',
      browserOpened: true,
      status: 'unconfigured'
    })
    expect(result.elicitation).toBeUndefined()
  })

  it('falls back when no elicitation server is provided', async () => {
    vi.mocked(tryOpenBrowser).mockClear()
    vi.mocked(tryOpenBrowser).mockResolvedValueOnce(true)
    const handler = buildOpenRelayHandler({
      serverName: 'test-server',
      publicUrl: 'http://127.0.0.1:8080'
    })
    const result = await handler()
    expect(tryOpenBrowser).toHaveBeenCalled()
    expect(result.elicitation).toBeUndefined()
  })

  it('stdio mode never elicits', async () => {
    const elicitation = makeElicitation(true)
    const handler = buildOpenRelayHandler({
      serverName: 'test-server',
      publicUrl: null,
      elicitation
    })
    const result = await handler()
    expect(elicitation.elicitInput).not.toHaveBeenCalled()
    expect(result.status).toBe('stdio_unsupported')
  })
})

describe('registerOpenRelayTool', () => {
  it('registers the config__open_relay tool with correct metadata', () => {
    const mcp: ToolRegistrar = {
      tool: vi.fn()
    }
    const serverName = 'test-server'
    const publicUrl = 'https://example.com'

    registerOpenRelayTool(mcp, serverName, publicUrl)

    expect(mcp.tool).toHaveBeenCalledWith(
      {
        name: 'config__open_relay',
        description: `Open the relay configuration form for ${serverName} in the user's browser.`
      },
      expect.any(Function)
    )
  })

  it('registered handler works correctly (fallback path)', async () => {
    const mcp = {
      tool: vi.fn() as Mock
    }
    registerOpenRelayTool(mcp as unknown as ToolRegistrar, 'test-server', 'https://example.com')

    const handler = mcp.tool.mock.calls[0][1]
    const result = await handler()

    expect(result.url).toBe('https://example.com/authorize')
    expect(result.status).toBe('unconfigured')
    expect(result.elicitation).toBeUndefined()
  })

  it('registered handler elicits when an elicitation server is wired', async () => {
    const mcp = {
      tool: vi.fn() as Mock
    }
    const elicitation = makeElicitation(true, 'accept')
    registerOpenRelayTool(mcp as unknown as ToolRegistrar, 'test-server', 'https://example.com', elicitation)

    const handler = mcp.tool.mock.calls[0][1]
    const result = await handler()

    expect(elicitation.elicitInput).toHaveBeenCalledTimes(1)
    expect(result.elicitation).toBe('accepted')
  })
})
