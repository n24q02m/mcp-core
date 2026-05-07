import { describe, expect, it, vi } from 'vitest'

vi.mock('../../src/relay/browser.js', () => ({ tryOpenBrowser: vi.fn().mockResolvedValue(true) }))

import { buildOpenRelayHandler } from '../../src/relay/tool-helpers.js'

describe('buildOpenRelayHandler -- HTTP mode', () => {
  it('returns the server-provided authorize URL', async () => {
    const handler = buildOpenRelayHandler({ serverName: 'test-server', publicUrl: 'http://127.0.0.1:8080' })
    const result = await handler()
    expect(result.url).toBe('http://127.0.0.1:8080/authorize')
    expect(result.status).toMatch(/configured|unconfigured/)
  })

  it('returns stdio_unsupported in stdio mode (null publicUrl)', async () => {
    const handler = buildOpenRelayHandler({ serverName: 'test-server', publicUrl: null })
    const result = await handler()
    expect(result.status).toBe('stdio_unsupported')
    expect(result.url).toBe('')
  })
})
