import { describe, expect, it } from 'vitest'

describe('TS bridge forwards notifications/tools/list_changed (D19)', () => {
  it('passes through notification frames from daemon stdout to bridge stdout', async () => {
    const { forwardDaemonMessageToBridge } = await import('../../src/transport/smart-stdio.js')

    const out: string[] = []
    const writer = (s: string) => {
      out.push(s)
    }

    const notification = JSON.stringify({
      jsonrpc: '2.0',
      method: 'notifications/tools/list_changed'
    })

    await forwardDaemonMessageToBridge(notification, writer)

    expect(out).toEqual([`${notification}\n`])
  })

  it('does not crash on malformed JSON', async () => {
    const { forwardDaemonMessageToBridge } = await import('../../src/transport/smart-stdio.js')

    const out: string[] = []
    const writer = (s: string) => {
      out.push(s)
    }

    await forwardDaemonMessageToBridge('not json', writer)

    // Malformed input should be passed through verbatim (existing behaviour)
    expect(out.length).toBe(1)
  })
})
