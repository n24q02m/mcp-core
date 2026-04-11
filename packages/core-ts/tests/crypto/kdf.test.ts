import { describe, expect, it } from 'vitest'
import { deriveAesKey } from '../../src/crypto/kdf.js'

describe('HKDF-SHA256 key derivation', () => {
  function makeSharedSecret(byte = 0x0b): ArrayBuffer {
    return new Uint8Array(32).fill(byte).buffer
  }

  it('returns an AES-GCM 256-bit CryptoKey', async () => {
    const key = await deriveAesKey(makeSharedSecret(), 'test-passphrase')

    expect(key).toBeInstanceOf(CryptoKey)
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 })
    expect(key.usages).toContain('encrypt')
    expect(key.usages).toContain('decrypt')
  })

  it('different passphrases produce different keys', async () => {
    const secret = makeSharedSecret()
    const key1 = await deriveAesKey(secret, 'passphrase-one')
    const key2 = await deriveAesKey(secret, 'passphrase-two')

    const raw1 = await crypto.subtle.exportKey('raw', key1)
    const raw2 = await crypto.subtle.exportKey('raw', key2)

    expect(Buffer.from(raw1).toString('hex')).not.toBe(Buffer.from(raw2).toString('hex'))
  })

  it('same inputs produce same key (deterministic)', async () => {
    const key1 = await deriveAesKey(makeSharedSecret(), 'same-passphrase')
    const key2 = await deriveAesKey(makeSharedSecret(), 'same-passphrase')

    const raw1 = await crypto.subtle.exportKey('raw', key1)
    const raw2 = await crypto.subtle.exportKey('raw', key2)

    expect(Buffer.from(raw1).toString('hex')).toBe(Buffer.from(raw2).toString('hex'))
  })
})
