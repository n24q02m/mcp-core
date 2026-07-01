import { afterEach, describe, expect, it } from 'vitest'
import type { SessionKv } from '../auth/session-store.js'
import { runHttpServer } from './local-server.js'

describe('runHttpServer delegatedOAuth sessionKv forwarding', () => {
  let close: (() => Promise<void>) | undefined

  afterEach(async () => {
    await close?.()
    close = undefined
  })

  it('forwards an injected sessionKv to the delegated OAuth app so pending-session state is durable', async () => {
    const puts: string[] = []
    const fakeKv: SessionKv = {
      async get() {
        return null
      },
      async put(key) {
        puts.push(key)
      },
      async delete() {}
    }

    const handle = await runHttpServer(
      () => {
        throw new Error('serverFactory should not be called for a bare /authorize request')
      },
      {
        serverName: 'test-delegated-server',
        port: 0,
        host: '127.0.0.1',
        delegatedOAuth: {
          flow: 'redirect',
          upstream: {
            authorizeUrl: 'https://upstream.example.test/authorize',
            tokenUrl: 'https://upstream.example.test/token',
            clientId: 'upstream-client'
          },
          onTokenReceived: async () => undefined,
          sessionKv: fakeKv
        }
      }
    )
    close = handle.close

    const url = new URL('/authorize', `http://${handle.host}:${handle.port}`)
    url.searchParams.set('client_id', 'local-browser')
    url.searchParams.set('redirect_uri', 'http://localhost/callback-done')
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('state', 'x')
    url.searchParams.set('code_challenge', 'y')
    url.searchParams.set('code_challenge_method', 'S256')

    const res = await fetch(url, { redirect: 'manual' })

    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toContain('upstream.example.test/authorize')
    // The injected sessionKv (not the in-memory fallback) must have received the
    // pending-session write -- this is what survives a container cold-start
    // between /authorize and /callback.
    expect(puts.length).toBe(1)
  })
})
