const encoder = new TextEncoder()
const decoder = new TextDecoder()

export interface EncryptResult {
  ciphertext: Uint8Array
  iv: Uint8Array
  tag: Uint8Array
}

export async function encrypt(key: CryptoKey, plaintext: string): Promise<EncryptResult> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encoded = encoder.encode(plaintext)
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded)

  // WebCrypto appends 16-byte GCM tag to ciphertext
  const combined = new Uint8Array(encrypted)
  const ciphertext = combined.slice(0, combined.length - 16)
  const tag = combined.slice(combined.length - 16)

  return { ciphertext, iv, tag }
}

export async function decrypt(
  key: CryptoKey,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag?: Uint8Array
): Promise<string> {
  let data: Uint8Array<ArrayBuffer>
  if (tag) {
    data = new Uint8Array(ciphertext.length + tag.length)
    data.set(ciphertext, 0)
    data.set(tag, ciphertext.length)
  } else {
    data = new Uint8Array(ciphertext)
  }
  const ivCopy = new Uint8Array(iv)
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivCopy }, key, data)
  return decoder.decode(decrypted)
}
