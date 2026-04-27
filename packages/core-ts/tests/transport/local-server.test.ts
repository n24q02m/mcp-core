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
      setupCompleteHook: (mark: (key?: string) => void) => {
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

  it('invokes 2-arg setupCompleteHook with both markComplete and markFailed', async () => {
    // Simulates the new failure-propagation wiring used by wet-mcp GDrive
    // device code flow. Google returning ``invalid_grant`` must be reflected
    // in /setup-status so the browser poll stops spinning.
    let receivedComplete: ((key?: string) => void) | null = null
    let receivedFailed: ((key?: string, error?: string) => void) | null = null
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-hook-2arg-${Date.now()}`,
      relaySchema: SCHEMA,
      port: 0,
      setupCompleteHook: (markComplete: (key?: string) => void, markFailed: (key?: string, error?: string) => void) => {
        receivedComplete = markComplete
        receivedFailed = markFailed
      }
    })
    try {
      expect(typeof receivedComplete).toBe('function')
      expect(typeof receivedFailed).toBe('function')

      if (receivedFailed) (receivedFailed as (k?: string, e?: string) => void)('gdrive', 'invalid_grant')
      const resp = await fetch(`http://${handle.host}:${handle.port}/setup-status`)
      const body = (await resp.json()) as Record<string, string>
      expect(body.gdrive).toBe('error:invalid_grant')
    } finally {
      await handle.close()
    }
  })
})

describe('runLocalServer — root bootstrap UX', () => {
  it('GET / redirects to /authorize with valid PKCE params', async () => {
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-root-${Date.now()}`,
      relaySchema: SCHEMA,
      port: 0
    })
    try {
      const resp = await fetch(`http://${handle.host}:${handle.port}/`, { redirect: 'manual' })
      expect(resp.status).toBe(302)
      const location = resp.headers.get('location') as string
      expect(location.startsWith('/authorize?')).toBe(true)
      const params = new URLSearchParams(location.replace(/^\/authorize\?/, ''))
      expect(params.get('client_id')).toBe('local-browser')
      expect(params.get('code_challenge_method')).toBe('S256')
      expect(params.get('code_challenge') as string).toHaveLength(43)
      expect(params.get('redirect_uri')).toContain('/callback-done')
    } finally {
      await handle.close()
    }
  })

  it('GET / followed produces credential form', async () => {
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-root-follow-${Date.now()}`,
      relaySchema: SCHEMA,
      port: 0
    })
    try {
      const resp = await fetch(`http://${handle.host}:${handle.port}/`, { redirect: 'follow' })
      expect(resp.status).toBe(200)
      const body = await resp.text()
      expect(body).toContain('Enter your credentials')
    } finally {
      await handle.close()
    }
  })

  it('GET /callback-done returns terminal success page', async () => {
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-callback-done-${Date.now()}`,
      relaySchema: SCHEMA,
      port: 0
    })
    try {
      const resp = await fetch(`http://${handle.host}:${handle.port}/callback-done`)
      expect(resp.status).toBe(200)
      const body = await resp.text()
      expect(body).toContain('Setup complete')
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

  it('handles sequential POST requests on /mcp (per-session transport)', async () => {
    // Regression history:
    //  - V1: shared stateless transport -> message ID collisions, 2nd POST 500.
    //  - V2: fresh stateless transport per request -> initialize OK but
    //    notifications/initialized + tools/list returned 500 because each
    //    request landed on a fresh transport with _initialized=false.
    //  - V3 (current): per-session map keyed by Mcp-Session-Id, sessionId
    //    minted on initialize, reused on subsequent POSTs. Mirrors Python
    //    StreamableHTTPSessionManager + the SDK's stateful-mode example.
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-sequential-${Date.now()}`,
      port: 0
    })
    try {
      const baseUrl = `http://${handle.host}:${handle.port}/mcp`
      const commonHeaders = {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream'
      }

      const init = await fetch(baseUrl, {
        method: 'POST',
        headers: commonHeaders,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-03-26',
            capabilities: {},
            clientInfo: { name: 'regression-test', version: '0' }
          }
        })
      })
      expect(init.status).toBe(200)
      const sessionId = init.headers.get('mcp-session-id')
      expect(sessionId).toBeTruthy()
      const sessionHeaders = {
        ...commonHeaders,
        'mcp-session-id': sessionId!,
        'mcp-protocol-version': '2025-03-26'
      }

      // notifications/initialized completes the handshake; SDK clients send
      // this automatically. Without it tools/list still works (no SDK
      // _initialized check on the server side) but exercising it here is
      // the actual regression: V2 stateless mode 500'd on this exact POST.
      const initialized = await fetch(baseUrl, {
        method: 'POST',
        headers: sessionHeaders,
        body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })
      })
      expect(initialized.status).toBe(202)

      const list = await fetch(baseUrl, {
        method: 'POST',
        headers: sessionHeaders,
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
      })
      expect(list.status).toBe(200)

      const list2 = await fetch(baseUrl, {
        method: 'POST',
        headers: sessionHeaders,
        body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list' })
      })
      expect(list2.status).toBe(200)
    } finally {
      await handle.close()
    }
  })
})

describe('runLocalServer — delegated mode', () => {
  it('serves /authorize via delegated redirect flow when delegatedOAuth set', async () => {
    const tokens: Array<Record<string, unknown>> = []
    const handle = await runLocalServer(makeMcpServer, {
      serverName: 'test-notion',
      delegatedOAuth: {
        flow: 'redirect',
        upstream: {
          authorizeUrl: 'https://example.com/oauth/authorize',
          tokenUrl: 'https://example.com/oauth/token',
          clientId: 'test-client',
          clientSecret: 'test-secret'
        },
        onTokenReceived: (t) => {
          tokens.push(t)
        }
      }
    })
    try {
      // /authorize without PKCE inputs should 400
      const res = await fetch(`http://${handle.host}:${handle.port}/authorize`)
      expect(res.status).toBe(400)
    } finally {
      await handle.close()
    }
  })

  it('rejects when both relaySchema and delegatedOAuth are set', async () => {
    await expect(
      runLocalServer(makeMcpServer, {
        serverName: 'test-conflict',
        relaySchema: SCHEMA,
        delegatedOAuth: {
          flow: 'redirect',
          upstream: { authorizeUrl: 'https://x.example', tokenUrl: 'https://y.example', clientId: 'c' },
          onTokenReceived: () => {}
        }
      })
    ).rejects.toThrow(/mutually exclusive/)
  })
})

describe('runLocalServer — authScope middleware', () => {
  it('invokes authScope middleware with JWT claims on authenticated /mcp request', async () => {
    const seen: Array<unknown> = []
    const handle = await runLocalServer(makeMcpServer, {
      serverName: `test-scope-${Date.now()}`,
      relaySchema: SCHEMA,
      authScope: async (claims, next) => {
        seen.push(claims)
        await next()
      }
    })
    try {
      // Without Bearer: 401 (authScope should NOT be called)
      const unauth = await fetch(`http://${handle.host}:${handle.port}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      })
      expect(unauth.status).toBe(401)
      expect(seen.length).toBe(0)
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

  it('forwards customCredentialFormHtml to the OAuth app', async () => {
    const customRenderer = (_schema: RelayConfigSchema, opts: { submitUrl: string }): string =>
      `<!DOCTYPE html><html><body><h1>Custom Forwarded</h1><a href="${opts.submitUrl}">x</a></body></html>`

    const handle: LocalServerHandle = await runLocalServer(makeMcpServer, {
      serverName: `test-custom-form-${Date.now()}`,
      relaySchema: SCHEMA,
      port: 0,
      customCredentialFormHtml: customRenderer
    })
    try {
      const params = new URLSearchParams({
        client_id: 'c',
        redirect_uri: 'http://x/cb',
        state: 's',
        code_challenge: 'challenge-placeholder-that-is-long-enough-for-s256',
        code_challenge_method: 'S256'
      })
      const resp = await fetch(`http://${handle.host}:${handle.port}/authorize?${params.toString()}`)
      expect(resp.status).toBe(200)
      const html = await resp.text()
      expect(html).toContain('<h1>Custom Forwarded</h1>')
      expect(html).not.toContain('Enter your credentials')
      expect(html).toContain('nonce=')
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
