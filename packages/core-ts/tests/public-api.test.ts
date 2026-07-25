import { describe, expect, it } from 'vitest'

import type { HttpRoute } from '../src/index.js'
import * as publicApi from '../src/index.js'

describe('public API surface', () => {
  it('re-exports registerOpenRelayTool + buildOpenRelayHandler from root', () => {
    expect(typeof publicApi.registerOpenRelayTool).toBe('function')
    expect(typeof publicApi.buildOpenRelayHandler).toBe('function')
  })

  it('exports the HttpRoute type for consumers registering extra routes', () => {
    // Type-level check: `tsc --noEmit` (via `bun run check`) fails unless
    // HttpRoute is exported from the root entry point with this shape.
    const route: HttpRoute = {
      method: 'GET',
      path: '/accounts/callback',
      handler: (_req, res) => {
        res.writeHead(204)
        res.end()
      }
    }
    expect(route.path).toBe('/accounts/callback')
  })
})
