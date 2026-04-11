import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { decrypt } from '../../src/crypto/aes.js'
import { deriveAesKey } from '../../src/crypto/kdf.js'

interface CryptoVectors {
  hkdf: {
    shared_secret_hex: string
    passphrase: string
    info: string
    derived_key_hex: string
  }
  aes_gcm: {
    plaintext: string
    iv_hex: string
    ciphertext_hex: string
    tag_hex: string
  }
}

const vectorsPath = resolve(import.meta.dirname ?? '.', '..', 'fixtures', 'crypto-vectors.json')
const vectors: CryptoVectors = JSON.parse(readFileSync(vectorsPath, 'utf-8'))

describe('cross-language crypto test vectors', () => {
  it('HKDF derives the expected key', async () => {
    const sharedSecret = new Uint8Array(Buffer.from(vectors.hkdf.shared_secret_hex, 'hex'))
    const key = await deriveAesKey(sharedSecret.buffer, vectors.hkdf.passphrase)

    const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key))
    const keyHex = Buffer.from(rawKey).toString('hex')

    expect(keyHex).toBe(vectors.hkdf.derived_key_hex)
  })

  it('AES-GCM encrypts to expected ciphertext with fixed IV', async () => {
    const sharedSecret = new Uint8Array(Buffer.from(vectors.hkdf.shared_secret_hex, 'hex'))
    const key = await deriveAesKey(sharedSecret.buffer, vectors.hkdf.passphrase)

    const iv = Buffer.from(vectors.aes_gcm.iv_hex, 'hex')
    const encoded = new TextEncoder().encode(vectors.aes_gcm.plaintext)

    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded)
    const combined = new Uint8Array(encrypted)
    const ciphertext = combined.slice(0, combined.length - 16)
    const tag = combined.slice(combined.length - 16)

    expect(Buffer.from(ciphertext).toString('hex')).toBe(vectors.aes_gcm.ciphertext_hex)
    expect(Buffer.from(tag).toString('hex')).toBe(vectors.aes_gcm.tag_hex)
  })

  it('AES-GCM decrypts vector ciphertext to expected plaintext', async () => {
    const sharedSecret = new Uint8Array(Buffer.from(vectors.hkdf.shared_secret_hex, 'hex'))
    const key = await deriveAesKey(sharedSecret.buffer, vectors.hkdf.passphrase)

    const ciphertext = new Uint8Array(Buffer.from(vectors.aes_gcm.ciphertext_hex, 'hex'))
    const iv = new Uint8Array(Buffer.from(vectors.aes_gcm.iv_hex, 'hex'))
    const tag = new Uint8Array(Buffer.from(vectors.aes_gcm.tag_hex, 'hex'))

    const plaintext = await decrypt(key, ciphertext, iv, tag)
    expect(plaintext).toBe(vectors.aes_gcm.plaintext)
  })
})
