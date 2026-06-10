import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { describe, expect, it, vi } from 'vitest'
import { runHttpServer } from '../../src/transport/local-server.js'

function makeMcpServer(): McpServer {
  return new McpServer({ name: 'test', version: '0.1.0' })
}

describe('runHttpServer best-effort cleanup', () => {
  it('continues cleanup when transport.close() throws', async () => {
    const handle = await runHttpServer(makeMcpServer, {
      serverName: `test-cleanup-transport-${Date.now()}`,
      port: 0
    })

    const baseUrl = `http://${handle.host}:${handle.port}/mcp`
    const commonHeaders = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream'
    }

    // Establish session 1
    await fetch(baseUrl, {
      method: 'POST',
      headers: commonHeaders,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't1', version: '0' } }
      })
    })

    // Establish session 2
    await fetch(baseUrl, {
      method: 'POST',
      headers: commonHeaders,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't2', version: '0' } }
      })
    })

    // Spy on close
    const transportCloseSpy = vi.spyOn(StreamableHTTPServerTransport.prototype, 'close')
    // Make it throw for the first call
    transportCloseSpy.mockRejectedValueOnce(new Error('Transport close failed'))

    await handle.close()

    // It should have been called at least twice (once per session).
    // Note: It might be called more if sessions close automatically during handle.close()
    // or through onsessionclosed.
    expect(transportCloseSpy.mock.calls.length).toBeGreaterThanOrEqual(2)

    transportCloseSpy.mockRestore()
  })

  it('continues cleanup when server.close() throws', async () => {
    const handle = await runHttpServer(makeMcpServer, {
      serverName: `test-cleanup-server-${Date.now()}`,
      port: 0
    })

    const baseUrl = `http://${handle.host}:${handle.port}/mcp`
    const commonHeaders = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream'
    }

    // Establish session 1
    await fetch(baseUrl, {
      method: 'POST',
      headers: commonHeaders,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't1', version: '0' } }
      })
    })

    // Establish session 2
    await fetch(baseUrl, {
      method: 'POST',
      headers: commonHeaders,
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't2', version: '0' } }
      })
    })

    // Spy on close
    const serverCloseSpy = vi.spyOn(McpServer.prototype, 'close')
    // Make it throw for the first call
    serverCloseSpy.mockRejectedValueOnce(new Error('Server close failed'))

    await handle.close()

    // It should have been called at least twice (once per session)
    expect(serverCloseSpy.mock.calls.length).toBeGreaterThanOrEqual(2)

    serverCloseSpy.mockRestore()
  })
})
