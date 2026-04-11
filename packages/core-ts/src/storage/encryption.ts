const encoder = new TextEncoder()
const decoder = new TextDecoder()

const SALT = encoder.encode('mcp-relay-config')
export const PBKDF2_ITERATIONS = 600_000
export const LEGACY_PBKDF2_ITERATIONS = 100_000

export async function deriveFileKey(
  machineId: string,
  username: string,
  iterations: number = PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(`${machineId}:${username}`),
    'PBKDF2',
    false,
    ['deriveKey']
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: SALT, iterations },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

export async function derivePassphraseKey(
  passphrase: string,
  iterations: number = PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: encoder.encode('mcp-relay-export'), iterations },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

export async function encryptData(key: CryptoKey, plaintext: string): Promise<Buffer> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(plaintext))
  // Format: [12-byte IV][ciphertext+tag]
  return Buffer.concat([iv, Buffer.from(encrypted)])
}

export async function decryptData(key: CryptoKey, data: Buffer): Promise<string> {
  const iv = data.subarray(0, 12)
  const ciphertext = data.subarray(12)
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(iv) },
    key,
    new Uint8Array(ciphertext)
  )
  return decoder.decode(decrypted)
}
