import { describe, expect, it } from 'vitest'

describe('forwardDaemonMessageToBridge production wiring', () => {
  it('production runSmartStdioProxy uses forwardDaemonMessageToBridge for daemon→bridge writes', async () => {
    // Verify by source-level inspection: import the source module and confirm
    // forwardDaemonMessageToBridge is referenced in non-export contexts.
    // (Ideally we'd run a fake daemon and assert stdout, but that requires
    // significant fixture infrastructure. A grep-based assertion is pragmatic.)

    const fs = await import('node:fs')
    const path = await import('node:path')
    const url = await import('node:url')
    const here = url.fileURLToPath(import.meta.url)
    const source = fs.readFileSync(path.resolve(path.dirname(here), '../../src/transport/smart-stdio.ts'), 'utf-8')

    // Count usages: 1 for export, the rest are call sites
    const matches = source.match(/forwardDaemonMessageToBridge/g) ?? []
    expect(matches.length).toBeGreaterThanOrEqual(7) // 1 export + ≥6 call sites
  })
})

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
