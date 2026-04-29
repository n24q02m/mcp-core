import { describe, expect, it } from 'vitest'

import * as publicApi from '../src/index.js'

describe('public API surface', () => {
  it('re-exports registerOpenRelayTool + buildOpenRelayHandler from root', () => {
    expect(typeof publicApi.registerOpenRelayTool).toBe('function')
    expect(typeof publicApi.buildOpenRelayHandler).toBe('function')
  })
})
