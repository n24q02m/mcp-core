import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { describe, expect, it } from 'vitest'
import { createRouter, htmlResponse, jsonResponse, parseFormBody, parseJsonBody } from '../../src/auth/router.js'

function startTestServer(handler: ReturnType<typeof createRouter>): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const server = createServer(handler)
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () => server.close()
      })
    })
  })
}

describe('createRouter', () => {
  it('routes GET requests by method and pathname', async () => {
    const handler = createRouter([
      {
        method: 'GET',
        path: '/hello',
        handler: (_req, res) => jsonResponse(res, 200, { ok: true })
      }
    ])
    const { url, close } = await startTestServer(handler)
    try {
      const resp = await fetch(`${url}/hello`)
      expect(resp.status).toBe(200)
      expect(await resp.json()).toEqual({ ok: true })
    } finally {
      close()
    }
  })

  it('returns 404 for unmatched routes', async () => {
    const handler = createRouter([])
    const { url, close } = await startTestServer(handler)
    try {
      const resp = await fetch(`${url}/nonexistent`)
      expect(resp.status).toBe(404)
      const body = (await resp.json()) as Record<string, string>
      expect(body.error).toBe('not_found')
    } finally {
      close()
    }
  })

  it('returns 500 when handler throws', async () => {
    const handler = createRouter([
      {
        method: 'GET',
        path: '/fail',
        handler: () => {
          throw new Error('boom')
        }
      }
    ])
    const { url, close } = await startTestServer(handler)
    try {
      const resp = await fetch(`${url}/fail`)
      expect(resp.status).toBe(500)
    } finally {
      close()
    }
  })

  it('routes different methods independently', async () => {
    const handler = createRouter([
      {
        method: 'GET',
        path: '/x',
        handler: (_r, res) => jsonResponse(res, 200, { method: 'GET' })
      },
      {
        method: 'POST',
        path: '/x',
        handler: (_r, res) => jsonResponse(res, 200, { method: 'POST' })
      }
    ])
    const { url, close } = await startTestServer(handler)
    try {
      const getResp = await fetch(`${url}/x`)
      expect(((await getResp.json()) as Record<string, string>).method).toBe('GET')
      const postResp = await fetch(`${url}/x`, { method: 'POST' })
      expect(((await postResp.json()) as Record<string, string>).method).toBe('POST')
    } finally {
      close()
    }
  })
})

describe('parseJsonBody', () => {
  it('parses JSON body correctly', async () => {
    const handler = createRouter([
      {
        method: 'POST',
        path: '/echo',
        handler: async (req, res) => {
          const body = await parseJsonBody(req)
          jsonResponse(res, 200, body)
        }
      }
    ])
    const { url, close } = await startTestServer(handler)
    try {
      const resp = await fetch(`${url}/echo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hello: 'world' })
      })
      expect(await resp.json()).toEqual({ hello: 'world' })
    } finally {
      close()
    }
  })

  it('rejects invalid JSON', async () => {
    const handler = createRouter([
      {
        method: 'POST',
        path: '/bad',
        handler: async (req, res) => {
          try {
            await parseJsonBody(req)
            jsonResponse(res, 200, { ok: true })
          } catch (err) {
            jsonResponse(res, 400, { error: (err as Error).message })
          }
        }
      }
    ])
    const { url, close } = await startTestServer(handler)
    try {
      const resp = await fetch(`${url}/bad`, {
        method: 'POST',
        body: 'not-json'
      })
      expect(resp.status).toBe(400)
    } finally {
      close()
    }
  })
})

describe('parseFormBody', () => {
  it('parses URL-encoded form body', async () => {
    const handler = createRouter([
      {
        method: 'POST',
        path: '/form',
        handler: async (req, res) => {
          const body = await parseFormBody(req)
          jsonResponse(res, 200, body)
        }
      }
    ])
    const { url, close } = await startTestServer(handler)
    try {
      const resp = await fetch(`${url}/form`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'key1=value1&key2=value2'
      })
      expect(await resp.json()).toEqual({ key1: 'value1', key2: 'value2' })
    } finally {
      close()
    }
  })
})

describe('jsonResponse', () => {
  it('writes JSON with correct content type', async () => {
    const handler = createRouter([
      {
        method: 'GET',
        path: '/j',
        handler: (_r, res) => jsonResponse(res, 201, { a: 1 })
      }
    ])
    const { url, close } = await startTestServer(handler)
    try {
      const resp = await fetch(`${url}/j`)
      expect(resp.status).toBe(201)
      expect(resp.headers.get('content-type')).toContain('application/json')
      expect(await resp.json()).toEqual({ a: 1 })
    } finally {
      close()
    }
  })
})

describe('htmlResponse', () => {
  it('writes HTML with correct content type', async () => {
    const handler = createRouter([
      {
        method: 'GET',
        path: '/h',
        handler: (_r, res) => htmlResponse(res, 200, '<html></html>')
      }
    ])
    const { url, close } = await startTestServer(handler)
    try {
      const resp = await fetch(`${url}/h`)
      expect(resp.status).toBe(200)
      expect(resp.headers.get('content-type')).toContain('text/html')
      expect(resp.headers.get('content-type')).toContain('utf-8')
      expect(await resp.text()).toBe('<html></html>')
    } finally {
      close()
    }
  })
})
