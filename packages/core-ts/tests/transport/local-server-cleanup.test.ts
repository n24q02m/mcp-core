import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { runHttpServer } from '../../src/transport/local-server.js'

describe('runHttpServer best-effort cleanup', () => {
  const makeMcpServer = () =>
    new McpServer(
      { name: 'test-server', version: '1.0.0' },
      { capabilities: { logging: {}, prompts: {}, resources: {}, tools: {} } }
    )

  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('continues cleaning up transports and servers even if some close() calls throw', async () => {
    const transportCloseSpy = vi.spyOn(StreamableHTTPServerTransport.prototype, 'close')
    transportCloseSpy.mockRejectedValueOnce(new Error('Transport close failed'))
    transportCloseSpy.mockResolvedValue(undefined)

    const serverCloseSpy = vi.spyOn(McpServer.prototype, 'close')
    serverCloseSpy.mockRejectedValueOnce(new Error('Server close failed'))
    serverCloseSpy.mockResolvedValue(undefined)

    const handle = await runHttpServer(makeMcpServer, {
      serverName: `test-cleanup-${Date.now()}`,
      port: 0
    })

    try {
      const baseUrl = `http://${handle.host}:${handle.port}/mcp`
      const initPayload = {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-03-26',
          capabilities: {},
          clientInfo: { name: 'test', version: '0' }
        }
      }

      const headers = {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream'
      }

      const resp1 = await fetch(baseUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(initPayload)
      })
      expect(resp1.status).toBe(200)

      const resp2 = await fetch(baseUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(initPayload)
      })
      expect(resp2.status).toBe(200)

      await handle.close()

      expect(transportCloseSpy).toHaveBeenCalledTimes(2)
      expect(serverCloseSpy).toHaveBeenCalledTimes(2)
    } finally {
      await handle.close().catch(() => {})
    }
  })
})
