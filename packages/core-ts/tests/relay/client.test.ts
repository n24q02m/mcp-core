import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { encrypt } from '../../src/crypto/aes.js'
import { deriveSharedSecret, exportPublicKey, generateKeyPair } from '../../src/crypto/ecdh.js'
import { deriveAesKey } from '../../src/crypto/kdf.js'
import { createSession, generatePassphrase, notifyComplete, pollForResult } from '../../src/relay/client.js'
import { WORDLIST } from '../../src/relay/wordlist.js'
import type { RelayConfigSchema } from '../../src/schema/types.js'

describe('WORDLIST', () => {
  it('should contain exactly 7776 words', () => {
    expect(WORDLIST.length).toBe(7776)
  })

  it('should contain only non-empty lowercase strings (may include hyphens)', () => {
    for (const word of WORDLIST) {
      expect(word).toMatch(/^[a-z]+(-[a-z]+)*$/)
    }
  })

  it('should have no duplicates', () => {
    const unique = new Set(WORDLIST)
    expect(unique.size).toBe(WORDLIST.length)
  })
})

describe('generatePassphrase', () => {
  function countWordsInPassphrase(passphrase: string): number {
    const sortedWords = [...WORDLIST].sort((a, b) => b.length - a.length)
    let remaining = passphrase
    let count = 0
    while (remaining.length > 0) {
      const matchingWord = sortedWords.find((w) => remaining.startsWith(`${w}-`) || remaining === w)
      if (!matchingWord) break
      count++
      remaining = remaining.substring(matchingWord.length)
      if (remaining.startsWith('-')) {
        remaining = remaining.substring(1)
      }
    }
    expect(remaining).toBe('') // Must match entirely
    return count
  }

  it('should return 4 words separated by hyphens by default', () => {
    const passphrase = generatePassphrase()
    expect(countWordsInPassphrase(passphrase)).toBe(4)
  })

  it('should respect custom word count', () => {
    const passphrase = generatePassphrase(6)
    expect(countWordsInPassphrase(passphrase)).toBe(6)
  })

  it('should only use words from the WORDLIST', () => {
    for (let i = 0; i < 20; i++) {
      const passphrase = generatePassphrase()
      expect(() => countWordsInPassphrase(passphrase)).not.toThrow()
    }
  })

  it('should produce different passphrases on successive calls', () => {
    const results = new Set<string>()
    for (let i = 0; i < 10; i++) {
      results.add(generatePassphrase())
    }
    // With ~52 bits entropy per passphrase, collisions are vanishingly rare
    expect(results.size).toBeGreaterThan(1)
  })
})

describe('createSession', () => {
  const mockSchema: RelayConfigSchema = {
    server: 'test-server',
    displayName: 'Test Server',
    fields: [{ key: 'token', label: 'Token', type: 'password', required: true }]
  }

  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      async () => new Response(JSON.stringify({ ok: true }), { status: 201 })
    )
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('should call POST /api/sessions', async () => {
    const _session = await createSession('https://relay.example.com', 'test-server', mockSchema)

    expect(fetch).toHaveBeenCalledOnce()
    const call = vi.mocked(fetch).mock.calls[0]
    expect(call[0]).toBe('https://relay.example.com/api/sessions')
    expect(call[1]?.method).toBe('POST')

    const body = JSON.parse(call[1]?.body as string)
    expect(body.sessionId).toBeDefined()
    expect(body.serverName).toBe('test-server')
    expect(body.schema).toEqual(mockSchema)
  })

  it('should return session with valid relayUrl containing fragment', async () => {
    const session = await createSession('https://relay.example.com', 'test-server', mockSchema)

    expect(session.sessionId).toHaveLength(64) // 32 bytes hex
    expect(session.passphrase).toMatch(/^[a-z-]+$/)
    expect(session.relayUrl).toContain('https://relay.example.com/authorize?s=')
    expect(session.relayUrl).toContain('#k=')
    expect(session.relayUrl).toContain('&p=')
    expect(session.keyPair.publicKey).toBeDefined()
    expect(session.keyPair.privateKey).toBeDefined()
  })

  it('should throw on non-ok response', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response('', { status: 500 }))

    await expect(createSession('https://relay.example.com', 'test-server', mockSchema)).rejects.toThrow(
      'Relay session creation failed: 500'
    )
  })
})

describe('pollForResult', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('should decrypt and return credentials on 200', async () => {
    // Simulate browser-side encryption
    const cliKeyPair = await generateKeyPair()
    const browserKeyPair = await generateKeyPair()
    const passphrase = 'alpha-bravo-charlie-delta'

    // Browser derives shared secret with CLI public key
    const sharedSecret = await deriveSharedSecret(browserKeyPair.privateKey, cliKeyPair.publicKey)
    const aesKey = await deriveAesKey(sharedSecret, passphrase)
    const credentials = { token: 'secret-123', api_key: 'key-456' }
    const { ciphertext, iv, tag } = await encrypt(aesKey, JSON.stringify(credentials))

    const browserPub = await exportPublicKey(browserKeyPair.publicKey)

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, opts) => {
      const _urlStr = typeof _url === 'string' ? _url : _url.toString()
      if (opts?.method === 'DELETE') {
        return new Response('', { status: 204 })
      }
      return new Response(
        JSON.stringify({
          browserPub,
          ciphertext: Buffer.from(ciphertext).toString('base64'),
          iv: Buffer.from(iv).toString('base64'),
          tag: Buffer.from(tag).toString('base64')
        }),
        { status: 200 }
      )
    })

    const session = {
      sessionId: 'test-session-id',
      keyPair: cliKeyPair,
      passphrase,
      relayUrl: 'https://relay.example.com/authorize?s=test-session-id'
    }

    const result = await pollForResult('https://relay.example.com', session, 10, 5000)
    expect(result).toEqual(credentials)

    // Session kept alive for bidirectional messaging (no DELETE on success)
    const deleteCalls = vi.mocked(fetch).mock.calls.filter((c) => c[1]?.method === 'DELETE')
    expect(deleteCalls).toHaveLength(0)
  })

  it('should handle cleanup failure gracefully and throw RELAY_SKIPPED when status is skipped', async () => {
    const cliKeyPair = await generateKeyPair()

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, opts) => {
      if (opts?.method === 'DELETE') {
        return Promise.reject(new Error('Network error during cleanup'))
      }
      return new Response(
        JSON.stringify({
          status: 'skipped'
        }),
        { status: 200 }
      )
    })

    const session = {
      sessionId: 'test-session-skipped',
      keyPair: cliKeyPair,
      passphrase: 'alpha-bravo-charlie-delta',
      relayUrl: 'https://relay.example.com/authorize?s=test-session-skipped'
    }

    await expect(pollForResult('https://relay.example.com', session, 10, 5000)).rejects.toThrow('RELAY_SKIPPED')
    expect(fetch).toHaveBeenCalledWith('https://relay.example.com/api/sessions/test-session-skipped', {
      method: 'DELETE'
    })
  })

  it('should throw on 404 (session expired)', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 404 }))

    const keyPair = await generateKeyPair()
    const session = {
      sessionId: 'expired-session',
      keyPair,
      passphrase: 'alpha-bravo-charlie-delta',
      relayUrl: 'https://relay.example.com/authorize?s=expired-session'
    }

    await expect(pollForResult('https://relay.example.com', session, 10, 5000)).rejects.toThrow(
      'Session expired or not found'
    )
  })

  it('should throw on unexpected status', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 500 }))

    const keyPair = await generateKeyPair()
    const session = {
      sessionId: 'error-session',
      keyPair,
      passphrase: 'alpha-bravo-charlie-delta',
      relayUrl: 'https://relay.example.com/authorize?s=error-session'
    }

    await expect(pollForResult('https://relay.example.com', session, 10, 5000)).rejects.toThrow(
      'Unexpected status: 500'
    )
  })

  it('should poll and timeout after deadline', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 202 }))

    const keyPair = await generateKeyPair()
    const session = {
      sessionId: 'slow-session',
      keyPair,
      passphrase: 'alpha-bravo-charlie-delta',
      relayUrl: 'https://relay.example.com/authorize?s=slow-session'
    }

    // Very short timeout + interval to test timeout path
    await expect(pollForResult('https://relay.example.com', session, 10, 50)).rejects.toThrow('Relay setup timed out')
  })

  it('should poll multiple times with 202 then succeed on 200', async () => {
    const cliKeyPair = await generateKeyPair()
    const browserKeyPair = await generateKeyPair()
    const passphrase = 'one-two-three-four'

    const sharedSecret = await deriveSharedSecret(browserKeyPair.privateKey, cliKeyPair.publicKey)
    const aesKey = await deriveAesKey(sharedSecret, passphrase)
    const { ciphertext, iv, tag } = await encrypt(aesKey, JSON.stringify({ key: 'value' }))
    const browserPub = await exportPublicKey(browserKeyPair.publicKey)

    let callCount = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, opts) => {
      if (opts?.method === 'DELETE') return new Response('', { status: 204 })
      callCount++
      if (callCount <= 2) {
        return new Response('', { status: 202 })
      }
      return new Response(
        JSON.stringify({
          browserPub,
          ciphertext: Buffer.from(ciphertext).toString('base64'),
          iv: Buffer.from(iv).toString('base64'),
          tag: Buffer.from(tag).toString('base64')
        }),
        { status: 200 }
      )
    })

    const session = {
      sessionId: 'poll-session',
      keyPair: cliKeyPair,
      passphrase,
      relayUrl: 'https://relay.example.com/authorize?s=poll-session'
    }

    const result = await pollForResult('https://relay.example.com', session, 10, 5000)
    expect(result).toEqual({ key: 'value' })
    expect(callCount).toBe(3) // 2 x 202, then 1 x 200
  })
})

describe('notifyComplete', () => {
  const baseUrl = 'https://relay.example.com'
  const sessionId = 'complete-session'

  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('POSTs a type:complete message then schedules DELETE after the grace period', async () => {
    const calls: Array<{ url: string; method?: string; body?: string }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = typeof input === 'string' ? input : (input as URL).toString()
      calls.push({
        url,
        method: (init?.method as string | undefined) ?? 'GET',
        body: typeof init?.body === 'string' ? init.body : undefined
      })
      if ((init?.method as string | undefined) === 'POST') {
        return new Response(JSON.stringify({ id: 'msg-xyz' }), { status: 201 })
      }
      return new Response('', { status: 204 })
    })

    await notifyComplete(baseUrl, sessionId, 'Setup complete!', { gracePeriodMs: 500 })

    // sendMessage fired immediately
    expect(calls.length).toBe(1)
    expect(calls[0].url).toBe(`${baseUrl}/api/sessions/${sessionId}/messages`)
    expect(calls[0].method).toBe('POST')
    expect(calls[0].body).toContain('"type":"complete"')
    expect(calls[0].body).toContain('"text":"Setup complete!"')

    // Before grace elapses: DELETE not issued yet
    await vi.advanceTimersByTimeAsync(499)
    expect(calls.filter((c) => c.method === 'DELETE').length).toBe(0)

    // After grace elapses: DELETE fired
    await vi.advanceTimersByTimeAsync(2)
    const deleteCalls = calls.filter((c) => c.method === 'DELETE')
    expect(deleteCalls.length).toBe(1)
    expect(deleteCalls[0].url).toBe(`${baseUrl}/api/sessions/${sessionId}`)
  })

  it('logs via console.error and returns without scheduling DELETE when sendMessage fails', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const calls: Array<{ url: string; method?: string }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = typeof input === 'string' ? input : (input as URL).toString()
      const method = (init?.method as string | undefined) ?? 'GET'
      calls.push({ url, method })
      if (method === 'POST') return new Response('server down', { status: 500 })
      return new Response('', { status: 204 })
    })

    await notifyComplete(baseUrl, sessionId, 'done', { gracePeriodMs: 10 })

    expect(calls.length).toBe(1)
    expect(calls[0].method).toBe('POST')
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("Failed to send relay 'complete' message"))

    await vi.advanceTimersByTimeAsync(1000)
    expect(calls.filter((c) => c.method === 'DELETE').length).toBe(0)
  })

  it("unref's the cleanup timer so it does not block process exit", async () => {
    const originalSetTimeout = globalThis.setTimeout
    const unrefSpy = vi.fn()
    const setTimeoutSpy = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((
      handler: () => void,
      ms?: number,
      ...args: unknown[]
    ) => {
      const timer = originalSetTimeout(handler, ms, ...args) as unknown as { unref?: () => void }
      timer.unref = unrefSpy
      return timer as unknown as ReturnType<typeof setTimeout>
    }) as typeof setTimeout)

    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ id: 'm' }), { status: 201 }))

    await notifyComplete(baseUrl, sessionId, 'done', { gracePeriodMs: 100 })

    expect(unrefSpy).toHaveBeenCalledOnce()
    setTimeoutSpy.mockRestore()
  })

  it('defaults text to "Setup complete!" and gracePeriodMs to 5000', async () => {
    const calls: Array<{ url: string; method?: string; body?: string }> = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = typeof input === 'string' ? input : (input as URL).toString()
      calls.push({
        url,
        method: (init?.method as string | undefined) ?? 'GET',
        body: typeof init?.body === 'string' ? init.body : undefined
      })
      if ((init?.method as string | undefined) === 'POST') {
        return new Response(JSON.stringify({ id: 'msg' }), { status: 201 })
      }
      return new Response('', { status: 204 })
    })

    await notifyComplete(baseUrl, sessionId)
    expect(calls[0].body).toContain('"text":"Setup complete!"')

    await vi.advanceTimersByTimeAsync(4999)
    expect(calls.filter((c) => c.method === 'DELETE').length).toBe(0)
    await vi.advanceTimersByTimeAsync(2)
    expect(calls.filter((c) => c.method === 'DELETE').length).toBe(1)
  })
})
