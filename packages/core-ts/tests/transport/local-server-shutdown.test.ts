import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { describe, expect, it, vi } from 'vitest'
import { runHttpServer } from '../../src/transport/local-server.js'

describe('runHttpServer shutdown best-effort', () => {
  it('continues to close other transports/servers if one fails', async () => {
    // Spy on prototypes to catch instances created inside runHttpServer
    const transportCloseSpy = vi
      .spyOn(StreamableHTTPServerTransport.prototype, 'close')
      .mockRejectedValueOnce(new Error('Transport close failed'))
      // biome-ignore lint/suspicious/noExplicitAny: mock expects the actual return type (Promise<void>)
      .mockResolvedValue(undefined as any)

    const serverCloseSpy = vi
      .spyOn(McpServer.prototype, 'close')
      .mockRejectedValueOnce(new Error('Server close failed'))
      // biome-ignore lint/suspicious/noExplicitAny: mock expects the actual return type (Promise<void>)
      .mockResolvedValue(undefined as any)

    const handle = await runHttpServer(() => new McpServer({ name: 'test', version: '0.1.0' }), {
      serverName: 'test-shutdown',
      port: 0
    })

    try {
      const baseUrl = `http://${handle.host}:${handle.port}/mcp`
      const headers = {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream'
      }

      // Create first session
      const resp1 = await fetch(baseUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-03-26',
            capabilities: {},
            clientInfo: { name: 'test-client-1', version: '0' }
          }
        })
      })
      expect(resp1.status).toBe(200)
      const sid1 = resp1.headers.get('mcp-session-id')
      expect(sid1).toBeTruthy()

      // Create second session
      const resp2 = await fetch(baseUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-03-26',
            capabilities: {},
            clientInfo: { name: 'test-client-2', version: '0' }
          }
        })
      })
      expect(resp2.status).toBe(200)
      const sid2 = resp2.headers.get('mcp-session-id')
      expect(sid2).toBeTruthy()
      expect(sid1).not.toBe(sid2)

      // Now close the handle. This should trigger the best-effort cleanup loop.
      await handle.close()

      // Verify both were called twice (one for each session)
      // The first call fails (due to mockRejectedValueOnce), but the second should still happen.
      expect(transportCloseSpy).toHaveBeenCalledTimes(2)
      expect(serverCloseSpy).toHaveBeenCalledTimes(2)
    } finally {
      // Ensure we clean up even if expectations fail, although handle.close() is what we're testing.
      // If handle.close() failed above, we try again just in case, but it's likely the server is already closing.
      try {
        await handle.close()
      } catch {
        /* ignore */
      }
      transportCloseSpy.mockRestore()
      serverCloseSpy.mockRestore()
    }
  })
})
