import { describe, expect, it, vi } from 'vitest'
import { tryOpenBrowser } from '../../src/relay/browser.js'
import { buildOpenRelayHandler, registerOpenRelayTool, type ToolRegistrar } from '../../src/relay/tool-helpers.js'

vi.mock('../../src/relay/browser.js', () => ({
  tryOpenBrowser: vi.fn().mockResolvedValue(true)
}))

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
    expect(tryOpenBrowser).toHaveBeenCalledWith('http://127.0.0.1:8080/authorize')
  })

  it('strips trailing slashes from publicUrl', async () => {
    const handler = buildOpenRelayHandler({
      serverName: 'test-server',
      publicUrl: 'http://127.0.0.1:8080/'
    })
    const result = await handler()
    expect(result.url).toBe('http://127.0.0.1:8080/authorize')
  })

  it('handles browser open failure', async () => {
    vi.mocked(tryOpenBrowser).mockResolvedValueOnce(false)
    const handler = buildOpenRelayHandler({
      serverName: 'test-server',
      publicUrl: 'http://127.0.0.1:8080'
    })
    const result = await handler()
    expect(result.browserOpened).toBe(false)
  })

  it('returns stdio_unsupported in stdio mode (null publicUrl)', async () => {
    const handler = buildOpenRelayHandler({ serverName: 'test-server', publicUrl: null })
    const result = await handler()
    expect(result.status).toBe('stdio_unsupported')
    expect(result.url).toBe('')
    expect(result.browserOpened).toBe(false)
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

  it('registered handler works correctly', async () => {
    const tool = vi.fn()
    const mcp: ToolRegistrar = { tool }
    registerOpenRelayTool(mcp, 'test-server', 'https://example.com')

    const handler = tool.mock.calls[0][1]
    const result = await handler()

    expect(result.url).toBe('https://example.com/authorize')
    expect(result.status).toBe('unconfigured')
  })
})
