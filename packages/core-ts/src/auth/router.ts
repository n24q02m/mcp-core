/**
 * Internal minimal HTTP router. Not exported from the package.
 * Matches requests by method + pathname, calls first matching handler.
 */
import type { IncomingMessage, ServerResponse } from 'node:http'

export type RequestHandler = (req: IncomingMessage, res: ServerResponse) => void | Promise<void>

interface Route {
  method: string
  path: string
  handler: RequestHandler
}

export function createRouter(routes: Route[]): RequestHandler {
  return async (req, res) => {
    const method = req.method?.toUpperCase() ?? 'GET'
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const pathname = url.pathname

    for (const route of routes) {
      if (route.method === method && route.path === pathname) {
        try {
          await route.handler(req, res)
        } catch {
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ error: 'internal_error' }))
          }
        }
        return
      }
    }

    res.writeHead(404, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'not_found' }))
  }
}

export async function parseJsonBody<T = Record<string, unknown>>(req: IncomingMessage): Promise<T> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf-8')))
      } catch {
        reject(new Error('Invalid JSON'))
      }
    })
    req.on('error', reject)
  })
}

export async function parseFormBody(req: IncomingMessage): Promise<Record<string, string>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', () => {
      const params = new URLSearchParams(Buffer.concat(chunks).toString('utf-8'))
      const result: Record<string, string> = {}
      for (const [key, value] of params) {
        result[key] = value
      }
      resolve(result)
    })
    req.on('error', reject)
  })
}

export function jsonResponse(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(body))
}

export function htmlResponse(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(html)
}
