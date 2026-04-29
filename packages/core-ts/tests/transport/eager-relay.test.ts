import { describe, expect, it, vi } from 'vitest'

vi.mock('../../src/relay/browser.js', () => ({
  tryOpenBrowser: vi.fn().mockResolvedValue(true)
}))

vi.mock('../../src/transport/local-server.js', () => ({
  runLocalServer: vi.fn().mockResolvedValue({ host: '127.0.0.1', port: 55123, close: vi.fn() })
}))

describe('runSmartStdioProxy eagerRelaySchema option (D18.1)', () => {
  it('spawns runLocalServer + tryOpenBrowser when eagerRelaySchema set and daemon cred_state=unconfigured', async () => {
    const { runSmartStdioProxy } = await import('../../src/transport/smart-stdio.js')
    const { runLocalServer } = await import('../../src/transport/local-server.js')
    const { tryOpenBrowser } = await import('../../src/relay/browser.js')

    vi.mocked(runLocalServer).mockClear()
    vi.mocked(tryOpenBrowser).mockClear()

    const fakeSchema = {
      server: 'better-notion-mcp',
      fields: [{ key: 'TOKEN', label: 'Token', type: 'password' as const }]
    }

    await runSmartStdioProxy('better-notion-mcp', ['node', '--version'], {
      env: {},
      eagerRelaySchema: fakeSchema,
      startupTimeout: 200,
      _testProbeOverride: { credState: 'unconfigured' }
    })

    expect(runLocalServer).toHaveBeenCalledOnce()
    expect(tryOpenBrowser).toHaveBeenCalledOnce()
  })

  it('does NOT spawn runLocalServer when eagerRelaySchema set but cred_state=configured', async () => {
    const { runSmartStdioProxy } = await import('../../src/transport/smart-stdio.js')
    const { runLocalServer } = await import('../../src/transport/local-server.js')

    vi.mocked(runLocalServer).mockClear()

    const fakeSchema = {
      server: 'better-notion-mcp',
      fields: [{ key: 'TOKEN', label: 'Token', type: 'password' as const }]
    }

    await runSmartStdioProxy('better-notion-mcp', ['node', '--version'], {
      env: {},
      eagerRelaySchema: fakeSchema,
      startupTimeout: 200,
      _testProbeOverride: { credState: 'configured' }
    })

    expect(runLocalServer).not.toHaveBeenCalled()
  })

  it('skips eager spawn when eagerRelaySchema omitted (lazy mode)', async () => {
    const { runSmartStdioProxy } = await import('../../src/transport/smart-stdio.js')
    const { runLocalServer } = await import('../../src/transport/local-server.js')

    vi.mocked(runLocalServer).mockClear()

    // _testProbeOverride with no credState prevents the stdio loop from
    // blocking on stdin, while still exercising the no-eagerRelaySchema path.
    await runSmartStdioProxy('better-notion-mcp', ['node', '--version'], {
      env: {},
      startupTimeout: 200,
      _testProbeOverride: {}
    })

    expect(runLocalServer).not.toHaveBeenCalled()
  })

  it('passes suppressLockFile:true to runLocalServer so OAuth AS lock is invisible to getActiveDaemon (C1 fix)', async () => {
    // After eager spawn, the runLocalServer call must include suppressLockFile:true
    // so the bootstrap OAuth AS does not write a <serverName>-<port>.lock file
    // that getActiveDaemon would match and treat as the real daemon.
    const { runSmartStdioProxy } = await import('../../src/transport/smart-stdio.js')
    const { runLocalServer } = await import('../../src/transport/local-server.js')

    vi.mocked(runLocalServer).mockClear()

    const fakeSchema = {
      server: 'better-notion-mcp',
      fields: [{ key: 'TOKEN', label: 'Token', type: 'password' as const }]
    }

    await runSmartStdioProxy('better-notion-mcp', ['node', '--version'], {
      env: {},
      eagerRelaySchema: fakeSchema,
      startupTimeout: 200,
      _testProbeOverride: { credState: 'unconfigured' }
    })

    expect(runLocalServer).toHaveBeenCalledOnce()
    const callOptions = vi.mocked(runLocalServer).mock.calls[0][1]
    expect(callOptions).toMatchObject({ suppressLockFile: true })
  })

  it('opens browser at root URL ("/") not "/authorize" for PKCE bootstrap (C2 fix)', async () => {
    // Opening /authorize directly returns 400 invalid_request because PKCE
    // params (client_id, redirect_uri, state, code_challenge) are missing.
    // The root URL ("/") auto-bootstraps PKCE and redirects to /authorize.
    const { runSmartStdioProxy } = await import('../../src/transport/smart-stdio.js')
    const { tryOpenBrowser } = await import('../../src/relay/browser.js')

    vi.mocked(tryOpenBrowser).mockClear()

    const fakeSchema = {
      server: 'better-notion-mcp',
      fields: [{ key: 'TOKEN', label: 'Token', type: 'password' as const }]
    }

    await runSmartStdioProxy('better-notion-mcp', ['node', '--version'], {
      env: {},
      eagerRelaySchema: fakeSchema,
      startupTimeout: 200,
      _testProbeOverride: { credState: 'unconfigured' }
    })

    expect(tryOpenBrowser).toHaveBeenCalledWith(expect.stringMatching(/\/$/))
    expect(tryOpenBrowser).not.toHaveBeenCalledWith(expect.stringContaining('/authorize'))
  })
})
