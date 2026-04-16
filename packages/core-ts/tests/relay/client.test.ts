import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { encrypt } from '../../src/crypto/aes.js'
import { deriveSharedSecret, exportPublicKey, generateKeyPair } from '../../src/crypto/ecdh.js'
import { deriveAesKey } from '../../src/crypto/kdf.js'
import { createSession, generatePassphrase, pollForResult } from '../../src/relay/client.js'
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
    const call = (fetch as any).mock.calls[0]
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
    expect(session.passphrase).toMatch(/^\w+-\w+-\w+-\w+$/)
    expect(session.relayUrl).toContain('https://relay.example.com/setup?s=')
    expect(session.relayUrl).toContain('#k=')
    expect(session.relayUrl).toContain('&p=')
    expect(session.keyPair.publicKey).toBeDefined()
    expect(session.keyPair.privateKey).toBeDefined()
  })

  it('should throw on non-ok response', async () => {
    ;(fetch as any).mockResolvedValueOnce(new Response('', { status: 500 }))

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
      relayUrl: 'https://relay.example.com/setup?s=test-session-id'
    }

    const result = await pollForResult('https://relay.example.com', session, 10, 5000)
    expect(result).toEqual(credentials)

    // Session kept alive for bidirectional messaging (no DELETE on success)
    const deleteCalls = (fetch as any).mock.calls.filter((c: any) => c[1]?.method === 'DELETE')
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
      relayUrl: 'https://relay.example.com/setup?s=test-session-skipped'
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
      relayUrl: 'https://relay.example.com/setup?s=expired-session'
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
      relayUrl: 'https://relay.example.com/setup?s=error-session'
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
      relayUrl: 'https://relay.example.com/setup?s=slow-session'
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
      relayUrl: 'https://relay.example.com/setup?s=poll-session'
    }

    const result = await pollForResult('https://relay.example.com', session, 10, 5000)
    expect(result).toEqual({ key: 'value' })
    expect(callCount).toBe(3) // 2 x 202, then 1 x 200
  })
})
