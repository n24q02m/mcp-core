import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import type { RelayConfigSchema } from '../../src/auth/credential-form.js'
import { JWTIssuer } from '../../src/oauth/jwt-issuer.js'
import { runHttpServer } from '../../src/transport/local-server.js'

const SCHEMA: RelayConfigSchema = {
  server: 'test-server',
  displayName: 'Test Server',
  description: 'Integration test server',
  fields: [{ key: 'api_key', label: 'API Key', type: 'text', required: true }]
}

function makeMcpServer(): McpServer {
  return new McpServer({ name: 'test', version: '0.1.0' })
}

describe('runHttpServer — JWT rejection', () => {
  let tempDir: string

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'mcp-core-rejection-test-'))
  })

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true })
  })

  it('rejects an expired token with 401 and invalid_token error', async () => {
    const serverName = `test-expired-${Date.now()}`
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()

    // Issue a token that is already expired
    const token = await issuer.issueAccessToken('user1', -10)

    const handle = await runHttpServer(makeMcpServer, {
      serverName,
      relaySchema: SCHEMA,
      jwtIssuer: issuer,
      port: 0
    })

    try {
      const resp = await fetch(`http://${handle.host}:${handle.port}/mcp`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 })
      })

      expect(resp.status).toBe(401)
      const authHeader = resp.headers.get('WWW-Authenticate')
      expect(authHeader).toContain('error="invalid_token"')
      expect(authHeader).toContain('resource_metadata=')
    } finally {
      await handle.close()
    }
  })

  it('rejects a token from a different issuer with 401 and invalid_token error', async () => {
    const serverName = `test-issuer-${Date.now()}`
    const otherServerName = `other-server-${Date.now()}`

    // Issuer for the server
    const serverIssuer = new JWTIssuer(serverName, join(tempDir, 'server'))
    await serverIssuer.init()

    // Other issuer that signs a token
    const otherIssuer = new JWTIssuer(otherServerName, join(tempDir, 'other'))
    await otherIssuer.init()
    const token = await otherIssuer.issueAccessToken('user1')

    const handle = await runHttpServer(makeMcpServer, {
      serverName,
      relaySchema: SCHEMA,
      jwtIssuer: serverIssuer,
      port: 0
    })

    try {
      const resp = await fetch(`http://${handle.host}:${handle.port}/mcp`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 })
      })

      expect(resp.status).toBe(401)
      const authHeader = resp.headers.get('WWW-Authenticate')
      expect(authHeader).toContain('error="invalid_token"')
    } finally {
      await handle.close()
    }
  })

  it('rejects a malformed token with 401 and invalid_token error', async () => {
    const serverName = `test-malformed-${Date.now()}`
    const issuer = new JWTIssuer(serverName, tempDir)
    await issuer.init()

    const handle = await runHttpServer(makeMcpServer, {
      serverName,
      jwtIssuer: issuer,
      relaySchema: SCHEMA,
      port: 0
    })

    try {
      const resp = await fetch(`http://${handle.host}:${handle.port}/mcp`, {
        method: 'POST',
        headers: {
          Authorization: 'Bearer not.a.valid.jwt',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 })
      })

      expect(resp.status).toBe(401)
      const authHeader = resp.headers.get('WWW-Authenticate')
      expect(authHeader).toContain('error="invalid_token"')
    } finally {
      await handle.close()
    }
  })
})
