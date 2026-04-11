import { describe, expect, it } from 'vitest'
import { decrypt, encrypt } from '../../src/crypto/aes.js'
import { deriveAesKey } from '../../src/crypto/kdf.js'

describe('AES-256-GCM encryption', () => {
  async function makeKey(passphrase = 'test-passphrase'): Promise<CryptoKey> {
    const secret = new Uint8Array(32).fill(0x0b).buffer
    return deriveAesKey(secret, passphrase)
  }

  it('encrypt + decrypt roundtrip works', async () => {
    const key = await makeKey()
    const plaintext = 'hello, mcp-relay!'

    const { ciphertext, iv, tag } = await encrypt(key, plaintext)
    const decrypted = await decrypt(key, ciphertext, iv, tag)

    expect(decrypted).toBe(plaintext)
  })

  it('IV is 12 bytes', async () => {
    const key = await makeKey()
    const { iv } = await encrypt(key, 'test')

    expect(iv).toBeInstanceOf(Uint8Array)
    expect(iv.length).toBe(12)
  })

  it('wrong key fails to decrypt', async () => {
    const key1 = await makeKey('key-one')
    const key2 = await makeKey('key-two')

    const { ciphertext, iv, tag } = await encrypt(key1, 'secret data')

    await expect(decrypt(key2, ciphertext, iv, tag)).rejects.toThrow()
  })

  it('tampered ciphertext fails to decrypt', async () => {
    const key = await makeKey()
    const { ciphertext, iv, tag } = await encrypt(key, 'integrity check')

    // Flip a bit in ciphertext
    const tampered = new Uint8Array(ciphertext)
    tampered[0] ^= 0xff

    await expect(decrypt(key, tampered, iv, tag)).rejects.toThrow()
  })
})
