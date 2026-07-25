/**
 * Integration tests for ``extraRoutes``. Starts a real HTTP server per test
 * and drives it with ``fetch``, same shape as local-server.test.ts.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('../../src/relay/browser.js', () => ({
  tryOpenBrowser: vi.fn().mockResolvedValue(true)
}))

import { type HttpServerHandle, runHttpServer } from '../../src/transport/local-server.js'

function makeMcpServer(): McpServer {
  return new McpServer({ name: 'test', version: '0.1.0' })
}

let handle: HttpServerHandle | undefined

afterEach(async () => {
  await handle?.close()
  handle = undefined
})

describe('runHttpServer extraRoutes', () => {
  it('calls a registered route and returns its response', async () => {
    handle = await runHttpServer(makeMcpServer, {
      serverName: `test-extra-${Date.now()}`,
      port: 0,
      extraRoutes: [
        {
          method: 'GET',
          path: '/accounts/callback',
          handler: (_req, res) => {
            res.writeHead(200, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ ok: true }))
          }
        }
      ]
    })

    const resp = await fetch(`http://${handle.host}:${handle.port}/accounts/callback`)

    expect(resp.status).toBe(200)
    expect(await resp.json()).toEqual({ ok: true })
  })

  it('passes the request through so the route can read the query string', async () => {
    let seenUrl = ''
    handle = await runHttpServer(makeMcpServer, {
      serverName: `test-extra-query-${Date.now()}`,
      port: 0,
      extraRoutes: [
        {
          method: 'GET',
          path: '/accounts/callback',
          handler: (req, res) => {
            seenUrl = req.url ?? ''
            res.writeHead(204)
            res.end()
          }
        }
      ]
    })

    const resp = await fetch(`http://${handle.host}:${handle.port}/accounts/callback?code=abc&state=xyz`)

    expect(resp.status).toBe(204)
    expect(seenUrl).toContain('code=abc')
    expect(seenUrl).toContain('state=xyz')
  })

  it('awaits an async route handler', async () => {
    handle = await runHttpServer(makeMcpServer, {
      serverName: `test-extra-async-${Date.now()}`,
      port: 0,
      extraRoutes: [
        {
          method: 'POST',
          path: '/accounts/add',
          handler: async (_req, res) => {
            await new Promise((r) => setTimeout(r, 10))
            res.writeHead(201)
            res.end('created')
          }
        }
      ]
    })

    const resp = await fetch(`http://${handle.host}:${handle.port}/accounts/add`, { method: 'POST' })

    expect(resp.status).toBe(201)
    expect(await resp.text()).toBe('created')
  })

  it('does not match when the method differs', async () => {
    handle = await runHttpServer(makeMcpServer, {
      serverName: `test-extra-method-${Date.now()}`,
      port: 0,
      extraRoutes: [
        {
          method: 'POST',
          path: '/accounts/add',
          handler: (_req, res) => {
            res.writeHead(201)
            res.end()
          }
        }
      ]
    })

    // GET on a POST-only route: no OAuth app here, so it must fall through to 404.
    const resp = await fetch(`http://${handle.host}:${handle.port}/accounts/add`)

    expect(resp.status).toBe(404)
  })

  it('leaves /health and /mcp to the built-in handlers even if a route claims them', async () => {
    let builtinOverridden = false
    handle = await runHttpServer(makeMcpServer, {
      serverName: `test-extra-builtin-${Date.now()}`,
      port: 0,
      extraRoutes: [
        {
          method: 'GET',
          path: '/health',
          handler: (_req, res) => {
            builtinOverridden = true
            res.writeHead(200)
            res.end('hijacked')
          }
        }
      ]
    })

    const resp = await fetch(`http://${handle.host}:${handle.port}/health`)

    expect(builtinOverridden).toBe(false)
    expect(await resp.json()).toMatchObject({ status: 'ok' })
  })

  it('behaves exactly as before when extraRoutes is omitted', async () => {
    handle = await runHttpServer(makeMcpServer, { serverName: `test-extra-none-${Date.now()}`, port: 0 })

    const health = await fetch(`http://${handle.host}:${handle.port}/health`)
    const missing = await fetch(`http://${handle.host}:${handle.port}/nope`)

    expect(health.status).toBe(200)
    expect(missing.status).toBe(404)
  })

  it('surfaces a throwing route as a 500 rather than killing the server', async () => {
    handle = await runHttpServer(makeMcpServer, {
      serverName: `test-extra-throw-${Date.now()}`,
      port: 0,
      extraRoutes: [
        {
          method: 'GET',
          path: '/boom',
          handler: () => {
            throw new Error('route exploded')
          }
        }
      ]
    })

    const resp = await fetch(`http://${handle.host}:${handle.port}/boom`)
    expect(resp.status).toBe(500)

    // server still alive
    const health = await fetch(`http://${handle.host}:${handle.port}/health`)
    expect(health.status).toBe(200)
  })
})
