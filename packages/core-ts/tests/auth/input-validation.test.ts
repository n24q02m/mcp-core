import { describe, expect, it } from 'vitest'
import {
  configureRelayLogin,
  loginGetHandler,
  loginPostHandler,
  type RelayLoginRequest,
  type RelayLoginResponse
} from '../../src/auth/relay-login.js'

function makeResponseStub() {
  let captured = ''
  let redirectUrl: string | null = null
  const res = {
    status: () => res,
    send: (body: unknown) => {
      captured = String(body)
      return res
    },
    set: () => res,
    redirect: (url: string) => {
      redirectUrl = url
      return res
    },
    cookie: () => res,
    header: () => res
  } as unknown as RelayLoginResponse
  return { res, getCaptured: () => captured, getRedirect: () => redirectUrl }
}

describe('input validation limits', () => {
  it('truncates long password in loginPostHandler', async () => {
    const longPassword = 'a'.repeat(2000)
    configureRelayLogin('a'.repeat(1024))
    const req: RelayLoginRequest = {
      body: { password: longPassword, next: '/authorize' },
      ip: '1.1.1.1'
    }
    const stub = makeResponseStub()
    await loginPostHandler(req, stub.res)
    // If it truncated to 1024, it should match our configured password
    expect(stub.getRedirect()).toBe('/authorize')
  })

  it('truncates long next param in loginGetHandler', async () => {
    const longNext = `/${'b'.repeat(3000)}`
    const stub = makeResponseStub()
    const resSubset = stub.res as unknown as Pick<RelayLoginResponse, 'send' | 'set'>
    await loginGetHandler({ query: { next: longNext } }, resSubset)
    const captured = stub.getCaptured()
    // It should contain a truncated version (2048 chars)
    expect(captured).toContain(`name="next" value="/${'b'.repeat(2047)}"`)
  })
})
