import { beforeEach, describe, expect, it } from 'vitest'
import {
  __resetRelayLoginState,
  configureRelayLogin,
  loginGetHandler,
  loginPostHandler,
  type RelayLoginRequest,
  type RelayLoginResponse
} from '../../src/auth/relay-login.js'

function makeResponseStub(): {
  res: RelayLoginResponse
  redirect: () => string | null
  body: () => string
} {
  let redirectUrl: string | null = null
  let capturedBody = ''
  const res: RelayLoginResponse = {
    status: (_code: number) => res,
    send: (body?: unknown) => {
      capturedBody = String(body ?? '')
      return res
    },
    cookie: (_name: string, _value: string, _options?: unknown) => res,
    set: (_name: string, _value: string) => res,
    redirect: (url: string) => {
      redirectUrl = url
      return res
    },
    header: (_name: string, _value: string) => res
  }
  return { res, redirect: () => redirectUrl, body: () => capturedBody }
}

describe('Open Redirect Targeted Tests', () => {
  beforeEach(() => {
    __resetRelayLoginState()
    configureRelayLogin('password123')
  })

  const payloads = [
    '//google.com',
    '/\\google.com',
    '\\google.com',
    '/ google.com',
    '/\tgoogle.com',
    '/\rgoogle.com',
    '/\ngoogle.com',
    'http://google.com',
    'https://google.com',
    'javascript:alert(1)',
    '//\\google.com',
    '///google.com',
    ' \t/google.com'
  ]

  describe('loginPostHandler', () => {
    it.each(payloads)('should block next="%s"', async (payload) => {
      const stub = makeResponseStub()
      const req: RelayLoginRequest = {
        body: { password: 'password123', next: payload },
        ip: '1.2.3.4'
      }
      await loginPostHandler(req, stub.res)
      expect(stub.redirect()).toBe('/authorize')
    })
  })

  describe('loginGetHandler', () => {
    it.each(payloads)('should block next="%s"', async (payload) => {
      const stub = makeResponseStub()
      const req: RelayLoginRequest = {
        query: { next: payload }
      }
      await loginGetHandler(req, stub.res)
      // The handler should have sanitized the 'next' value used in the form
      expect(stub.body()).toContain('name="next" value="/authorize"')
    })
  })
})
