import { hkdfSync } from 'node:crypto'

const encoder = new TextEncoder()

const INFO = encoder.encode('mcp-relay')
const JWT_SIGNING_INFO_PREFIX = 'mcp-jwt-signing-key-v1:'

export async function deriveAesKey(sharedSecret: ArrayBuffer, passphrase: string): Promise<CryptoKey> {
  const salt = encoder.encode(passphrase)
  const keyMaterial = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey'])

  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: INFO },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )
}

/**
 * Derive a deterministic 32-byte Ed25519 seed for OAuth JWT signing.
 *
 * Used in HTTP multi-user mode (CREDENTIAL_SECRET set) so every container
 * replica converges on the SAME signing key without a shared volume or
 * external secret store. Domain-separated per server via the HKDF info label.
 *
 * HKDF-SHA256 with IKM = secret, empty salt, info =
 * `mcp-jwt-signing-key-v1:<serverName>`. Byte-identical to core-py's
 * `derive_jwt_signing_seed` for the same inputs (enforced by the shared
 * crypto-vectors fixture).
 */
export function deriveJwtSigningSeed(secret: string, serverName: string): Buffer {
  const info = encoder.encode(`${JWT_SIGNING_INFO_PREFIX}${serverName}`)
  return Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'utf-8'), Buffer.alloc(0), info, 32))
}
