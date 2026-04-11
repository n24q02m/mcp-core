import { describe, expect, it } from 'vitest'
import {
  decryptData,
  deriveFileKey,
  derivePassphraseKey,
  encryptData,
  LEGACY_PBKDF2_ITERATIONS,
  PBKDF2_ITERATIONS
} from '../../src/storage/encryption.js'

describe('deriveFileKey', () => {
  it('returns an AES-GCM CryptoKey', async () => {
    const key = await deriveFileKey('machine-123', 'alice')
    expect(key).toBeDefined()
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 })
    expect(key.usages).toContain('encrypt')
    expect(key.usages).toContain('decrypt')
  })

  it('same inputs produce same key (deterministic)', async () => {
    const key1 = await deriveFileKey('id-abc', 'bob')
    const key2 = await deriveFileKey('id-abc', 'bob')

    // Encrypt with key1, decrypt with key2 should work
    const encrypted = await encryptData(key1, 'test data')
    const decrypted = await decryptData(key2, encrypted)
    expect(decrypted).toBe('test data')
  })

  it('different machine-id produces different key', async () => {
    const key1 = await deriveFileKey('machine-A', 'user')
    const key2 = await deriveFileKey('machine-B', 'user')

    const encrypted = await encryptData(key1, 'secret')
    await expect(decryptData(key2, encrypted)).rejects.toThrow()
  })

  it('different username produces different key', async () => {
    const key1 = await deriveFileKey('machine-1', 'alice')
    const key2 = await deriveFileKey('machine-1', 'bob')

    const encrypted = await encryptData(key1, 'secret')
    await expect(decryptData(key2, encrypted)).rejects.toThrow()
  })
})

describe('encrypt + decrypt roundtrip', () => {
  it('encrypts and decrypts plain text', async () => {
    const key = await deriveFileKey('test-machine', 'test-user')
    const plaintext = 'hello, config!'

    const encrypted = await encryptData(key, plaintext)
    expect(encrypted).toBeInstanceOf(Buffer)
    expect(encrypted.length).toBeGreaterThan(12) // IV + ciphertext

    const decrypted = await decryptData(key, encrypted)
    expect(decrypted).toBe(plaintext)
  })

  it('handles empty string', async () => {
    const key = await deriveFileKey('m', 'u')
    const encrypted = await encryptData(key, '')
    const decrypted = await decryptData(key, encrypted)
    expect(decrypted).toBe('')
  })

  it('handles unicode text', async () => {
    const key = await deriveFileKey('m', 'u')
    const text = 'Xin chao the gioi! Emoji: Tieng Viet co dau'
    const encrypted = await encryptData(key, text)
    const decrypted = await decryptData(key, encrypted)
    expect(decrypted).toBe(text)
  })

  it('produces different ciphertext each time (random IV)', async () => {
    const key = await deriveFileKey('m', 'u')
    const enc1 = await encryptData(key, 'same')
    const enc2 = await encryptData(key, 'same')
    expect(enc1.equals(enc2)).toBe(false)
  })

  it('wrong key fails to decrypt', async () => {
    const key1 = await deriveFileKey('m1', 'u1')
    const key2 = await deriveFileKey('m2', 'u2')

    const encrypted = await encryptData(key1, 'secret data')
    await expect(decryptData(key2, encrypted)).rejects.toThrow()
  }, 60000)
})

describe('PBKDF2 iterations', () => {
  it('different iterations produce different keys', async () => {
    const keyCurrent = await deriveFileKey('m', 'u', PBKDF2_ITERATIONS)
    const keyLegacy = await deriveFileKey('m', 'u', LEGACY_PBKDF2_ITERATIONS)

    const encrypted = await encryptData(keyCurrent, 'secret')
    await expect(decryptData(keyLegacy, encrypted)).rejects.toThrow()
  }, 60000)

  it('legacy key can decrypt legacy-encrypted data', async () => {
    const keyLegacy = await deriveFileKey('m', 'u', LEGACY_PBKDF2_ITERATIONS)
    const encrypted = await encryptData(keyLegacy, 'migration test')
    const decrypted = await decryptData(keyLegacy, encrypted)
    expect(decrypted).toBe('migration test')
  }, 60000)

  it('passphrase key with different iterations produces different keys', async () => {
    const keyCurrent = await derivePassphraseKey('pass', PBKDF2_ITERATIONS)
    const keyLegacy = await derivePassphraseKey('pass', LEGACY_PBKDF2_ITERATIONS)

    const encrypted = await encryptData(keyCurrent, 'secret')
    await expect(decryptData(keyLegacy, encrypted)).rejects.toThrow()
  }, 60000)
})
