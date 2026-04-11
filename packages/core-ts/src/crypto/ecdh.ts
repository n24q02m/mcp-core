const ALGORITHM = { name: 'ECDH', namedCurve: 'P-256' }

export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ALGORITHM, true, ['deriveKey', 'deriveBits'])
}

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key)
  return Buffer.from(raw).toString('base64url')
}

export async function importPublicKey(base64url: string): Promise<CryptoKey> {
  const raw = Buffer.from(base64url, 'base64url')
  return crypto.subtle.importKey('raw', raw, ALGORITHM, true, [])
}

export async function deriveSharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256)
}
