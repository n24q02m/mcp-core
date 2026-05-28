import { describe, expect, it, beforeEach } from 'vitest'
import {
  __resetRelayLoginState,
  configureRelayLogin,
  loginPostHandler,
  loginGetHandler,
  type RelayLoginRequest,
  type RelayLoginResponse
} from '../../src/auth/relay-login.js'

function makeResponseStub() {
  let redirectUrl: string | null = null
  let capturedBody: string = ''
  const res: any = {
    status: () => res,
    send: (body: any) => {
      capturedBody = String(body)
      return res
    },
    cookie: () => res,
    set: () => res,
    redirect: (url: string) => {
      redirectUrl = url
      return res
    }
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
      const req: any = {
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
      const req: any = {
        query: { next: payload }
      }
      await loginGetHandler(req, stub.res)
      // The handler should have sanitized the 'next' value used in the form
      expect(stub.body()).toContain('name="next" value="/authorize"')
    })
  })
})
