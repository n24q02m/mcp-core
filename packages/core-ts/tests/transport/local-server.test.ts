/**
 * Integration tests for the ``runLocalServer`` entry point.
 *
 * Starts a real HTTP server per test and drives requests via ``fetch``.
 * Covers both the OAuth-enabled path (relaySchema provided) and the
 * unauthenticated path (godot-style servers without relay config).
 */

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import type { RelayConfigSchema } from '../../src/auth/credential-form.js'
import { type LocalServerHandle, runLocalServer } from '../../src/transport/local-server.js'

const SCHEMA: RelayConfigSchema = {
  server: 'test-server',
  displayName: 'Test Server',
  description: 'Integration test server',
  fields: [{ key: 'api_key', label: 'API Key', type: 'text', required: true }]
}

function makeMcpServer(): McpServer {
  return new McpServer({ name: 'test', version: '0.1.0' })
}

let tempKeysDir: string
let originalKeysEnv: string | undefined

beforeEach(() => {
  tempKeysDir = mkdtempSync(join(tmpdir(), 'mcp-core-local-server-'))
  // JWTIssuer default keys directory is derived at import time via env-paths.
  // We don't override it here -- createLocalOAuthApp creates its own JWTIssuer
  // using defaults. Tests that care about isolated keys should inject their
  // own JWTIssuer via createLocalOAuthApp directly (covered in OAuth tests).
  originalKeysEnv = process.env.MCP_CORE_KEYS_DIR
})

afterEach(() => {
  rmSync(tempKeysDir, { recursive: true, force: true })
  if (originalKeysEnv === undefined) delete process.env.MCP_CORE_KEYS_DIR
  else process.env.MCP_CORE_KEYS_DIR = originalKeysEnv
})

describe('runLocalServer with relaySchema (OAuth enabled)', () => {
  it('serves /authorize form and requires Bearer on /mcp', async () => {
    const handle: LocalServerHandle = await runLocalServer(makeMcpServer, {
      serverName: `test-oauth-${Date.now()}`,
      relaySchema: SCHEMA,
      port: 0
    })
    try {
      // /authorize renders form when PKCE params are present.
      const params = new URLSearchParams({
        client_id: 'test-client',
        redirect_uri: 'http://localhost:5555/callback',
        state: 'xyz',
        code_challenge: 'challenge-placeholder-that-is-long-enough-for-s256',
        code_challenge_method: 'S256'
      })
      const authResp = await fetch(`http://${handle.host}:${handle.port}/authorize?${params.toString()}`)
      expect(authResp.status).toBe(200)
      expect(authResp.headers.get('content-type')).toContain('text/html')
      const html = await authResp.text()
      expect(html).toContain('Test Server')

      // /mcp without Authorization -> 401 Bearer challenge.
      const mcpResp = await fetch(`http://${handle.host}:${handle.port}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', id: 1 })
      })
      expect(mcpResp.status).toBe(401)
      expect(mcpResp.headers.get('www-authenticate')).toContain('Bearer')
    } finally {
      await handle.close()
    }
  })

  it('returns 401 with invalid_token for malformed Bearer', async () => {
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-invalid-token-${Date.now()}`,
      relaySchema: SCHEMA,
      port: 0
    })
    try {
      const resp = await fetch(`http://${handle.host}:${handle.port}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer not-a-real-jwt'
        },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', id: 1 })
      })
      expect(resp.status).toBe(401)
      expect(resp.headers.get('www-authenticate')).toContain('invalid_token')
    } finally {
      await handle.close()
    }
  })

  it('invokes setupCompleteHook with a markComplete function', async () => {
    let receivedMark: ((key?: string) => void) | null = null
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-hook-${Date.now()}`,
      relaySchema: SCHEMA,
      port: 0,
      setupCompleteHook: (mark) => {
        receivedMark = mark
      }
    })
    try {
      expect(receivedMark).not.toBeNull()
      expect(typeof receivedMark).toBe('function')

      // Poll /setup-status: should reflect markComplete call.
      const beforeResp = await fetch(`http://${handle.host}:${handle.port}/setup-status`)
      const beforeBody = (await beforeResp.json()) as Record<string, string>
      expect(beforeBody.gdrive).toBe('idle')

      if (receivedMark) (receivedMark as (key?: string) => void)('gdrive')

      const afterResp = await fetch(`http://${handle.host}:${handle.port}/setup-status`)
      const afterBody = (await afterResp.json()) as Record<string, string>
      expect(afterBody.gdrive).toBe('complete')
    } finally {
      await handle.close()
    }
  })
})

describe('runLocalServer without relaySchema (godot-style)', () => {
  it('serves /mcp without auth and returns 404 for /authorize', async () => {
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-no-auth-${Date.now()}`,
      port: 0
    })
    try {
      // /mcp is reachable without Authorization header. MCP transport may
      // respond with its own status code but NOT a 401 (no Bearer enforced).
      const mcpResp = await fetch(`http://${handle.host}:${handle.port}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'initialize', id: 1 })
      })
      expect(mcpResp.status).not.toBe(401)

      // /authorize -> 404 since no OAuth app is mounted.
      const authResp = await fetch(`http://${handle.host}:${handle.port}/authorize`)
      expect(authResp.status).toBe(404)
    } finally {
      await handle.close()
    }
  })

  it('does not invoke setupCompleteHook when relaySchema absent', async () => {
    let called = false
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-no-hook-${Date.now()}`,
      port: 0,
      setupCompleteHook: () => {
        called = true
      }
    })
    try {
      expect(called).toBe(false)
    } finally {
      await handle.close()
    }
  })
})

describe('runLocalServer lifecycle', () => {
  it('port 0 auto-assigns a non-zero port', async () => {
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-autoport-${Date.now()}`,
      port: 0
    })
    try {
      expect(handle.port).toBeGreaterThan(0)
      expect(handle.host).toBe('127.0.0.1')
    } finally {
      await handle.close()
    }
  })

  it('/health responds with ok status regardless of auth config', async () => {
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-health-${Date.now()}`,
      relaySchema: SCHEMA,
      port: 0
    })
    try {
      const resp = await fetch(`http://${handle.host}:${handle.port}/health`)
      expect(resp.status).toBe(200)
      const body = (await resp.json()) as Record<string, string>
      expect(body.status).toBe('ok')
    } finally {
      await handle.close()
    }
  })

  it('close() cleanly shuts down the HTTP server', async () => {
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-close-${Date.now()}`,
      port: 0
    })
    const { host, port } = handle
    await handle.close()

    // After close, the port is no longer accepting connections.
    await expect(
      fetch(`http://${host}:${port}/health`, {
        signal: AbortSignal.timeout(1000)
      })
    ).rejects.toThrow()
  })
})
