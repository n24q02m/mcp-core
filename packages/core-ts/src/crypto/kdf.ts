const INFO = new TextEncoder().encode('mcp-relay')

export async function deriveAesKey(sharedSecret: ArrayBuffer, passphrase: string): Promise<CryptoKey> {
  const salt = new TextEncoder().encode(passphrase)
  const keyMaterial = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey'])

  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: INFO },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )
}
