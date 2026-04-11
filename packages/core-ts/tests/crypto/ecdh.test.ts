import { describe, expect, it } from 'vitest'
import { deriveSharedSecret, exportPublicKey, generateKeyPair, importPublicKey } from '../../src/crypto/ecdh.js'

describe('ECDH P-256', () => {
  it('generates a valid keypair', async () => {
    const kp = await generateKeyPair()
    expect(kp.publicKey).toBeInstanceOf(CryptoKey)
    expect(kp.privateKey).toBeInstanceOf(CryptoKey)
  })

  it('exports and imports public key as base64url', async () => {
    const kp = await generateKeyPair()
    const exported = await exportPublicKey(kp.publicKey)
    expect(typeof exported).toBe('string')
    expect(exported.length).toBeGreaterThan(0)

    const imported = await importPublicKey(exported)
    expect(imported).toBeInstanceOf(CryptoKey)
  })

  it('derives identical shared secret on both sides', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()

    const secretA = await deriveSharedSecret(alice.privateKey, bob.publicKey)
    const secretB = await deriveSharedSecret(bob.privateKey, alice.publicKey)

    expect(Buffer.from(secretA).toString('hex')).toBe(Buffer.from(secretB).toString('hex'))
  })

  it('derives different secrets with different keypairs', async () => {
    const alice = await generateKeyPair()
    const bob = await generateKeyPair()
    const charlie = await generateKeyPair()

    const secretAB = await deriveSharedSecret(alice.privateKey, bob.publicKey)
    const secretAC = await deriveSharedSecret(alice.privateKey, charlie.publicKey)

    expect(Buffer.from(secretAB).toString('hex')).not.toBe(Buffer.from(secretAC).toString('hex'))
  })
})
