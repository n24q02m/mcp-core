import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { describe, expect, it } from 'vitest'

import { StreamableHTTPServer } from '../../src/transport/streamable-http.js'

describe('StreamableHTTPServer', () => {
  it('exposes host and port properties', () => {
    const server = new McpServer({ name: 'test', version: '0.0.0' })
    const http = new StreamableHTTPServer({
      server,
      host: '127.0.0.1',
      port: 9876
    })
    expect(http.host).toBe('127.0.0.1')
    expect(http.port).toBe(9876)
  })

  it('defaults host to 127.0.0.1 when not specified', () => {
    const server = new McpServer({ name: 'test', version: '0.0.0' })
    const http = new StreamableHTTPServer({ server, port: 9000 })
    expect(http.host).toBe('127.0.0.1')
  })

  it('exposes the underlying transport for advanced use', () => {
    const server = new McpServer({ name: 'test', version: '0.0.0' })
    const http = new StreamableHTTPServer({ server, port: 9000 })
    expect(http.transport).toBeDefined()
  })

  it('connect() is idempotent — multiple calls do not re-connect', async () => {
    const server = new McpServer({ name: 'test', version: '0.0.0' })
    const http = new StreamableHTTPServer({ server, port: 9000 })
    await http.connect()
    await http.connect()
    // Should not throw; second call is a no-op.
    await http.close()
  })
})
