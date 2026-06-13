/**
 * RSA JWT Issuer and JWKS generation for TypeScript MCP servers.
 * Uses jose (industry-standard, zero-dep, Web Crypto compatible).
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import * as jose from 'jose'

const DEFAULT_KEYS_DIR = join(homedir(), '.mcp-core', 'jwt-keys')

export class JWTIssuer {
  private serverName: string
  private keysDir: string
  private privateKeyPath: string
  private publicKeyPath: string
  private kid = 'key-1'
  private privateKey: jose.CryptoKey | null = null
  private publicKey: jose.CryptoKey | null = null
  private _initialized = false

  constructor(serverName: string, keysDir = DEFAULT_KEYS_DIR) {
    this.serverName = serverName
    this.keysDir = keysDir
    this.privateKeyPath = join(this.keysDir, `${serverName}_private.pem`)
    this.publicKeyPath = join(this.keysDir, `${serverName}_public.pem`)
  }

  /**
   * Securely import a private key from PEM, ensuring binary material is cleared
   * from mutable memory and the resulting CryptoKey is non-extractable.
   */
  private async importPrivateKey(pem: string | Buffer): Promise<jose.CryptoKey> {
    const s = typeof pem === 'string' ? pem : pem.toString('utf-8')
    const b64 = s.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, '')
    const der = Buffer.from(b64, 'base64')
    const key = await crypto.subtle.importKey(
      'pkcs8',
      der,
      {
        name: 'RSASSA-PKCS1-v1_5', // RS256
        hash: 'SHA-256'
      },
      false,
      ['sign']
    )
    der.fill(0)
    return key
  }

  /** Must call before using issuer — loads or generates RSA keys. */
  async init(): Promise<void> {
    if (this._initialized) return
    mkdirSync(this.keysDir, { recursive: true, mode: 0o700 })

    if (existsSync(this.privateKeyPath) && existsSync(this.publicKeyPath)) {
      const privatePemBuffer = readFileSync(this.privateKeyPath)
      const publicPem = readFileSync(this.publicKeyPath, 'utf-8')

      this.privateKey = await this.importPrivateKey(privatePemBuffer)
      this.publicKey = await jose.importSPKI(publicPem, 'RS256', { extractable: true })

      privatePemBuffer.fill(0)
    } else {
      const { publicKey, privateKey: generatedPrivateKey } = await jose.generateKeyPair('RS256', {
        modulusLength: 2048,
        extractable: true
      })

      const privatePem = await jose.exportPKCS8(generatedPrivateKey)
      const publicPem = await jose.exportSPKI(publicKey)

      writeFileSync(this.privateKeyPath, privatePem, { mode: 0o600 })
      writeFileSync(this.publicKeyPath, publicPem, { mode: 0o644 })

      const privatePemBuffer = Buffer.from(privatePem)
      // Re-import with extractable: false for in-memory storage
      this.privateKey = await this.importPrivateKey(privatePemBuffer)
      this.publicKey = await jose.importSPKI(publicPem, 'RS256', { extractable: true })

      privatePemBuffer.fill(0)
    }
    this._initialized = true
  }

  /** Return JWKS payload for /.well-known/jwks.json */
  async getJwks(): Promise<jose.JSONWebKeySet> {
    if (!this.publicKey) throw new Error('JWTIssuer not initialized')
    const jwk = await jose.exportJWK(this.publicKey)
    jwk.kid = this.kid
    jwk.use = 'sig'
    jwk.alg = 'RS256'
    return { keys: [jwk] }
  }

  /** Issue an RS256 JWT access token (``typ="access"``). */
  async issueAccessToken(sub: string, expiresInSeconds = 3600): Promise<string> {
    if (!this.privateKey) throw new Error('JWTIssuer not initialized')
    return new jose.SignJWT({ sub, typ: 'access' })
      .setProtectedHeader({ alg: 'RS256', kid: this.kid })
      .setIssuer(this.serverName)
      .setAudience(this.serverName)
      .setIssuedAt()
      .setExpirationTime(`${expiresInSeconds}s`)
      .sign(this.privateKey)
  }

  /**
   * Issue an RS256 JWT refresh token (``typ="refresh"``).
   *
   * Defaults to a 30-day (2592000s) lifetime so long-running MCP clients can
   * mint fresh access tokens without forcing the user back through the
   * browser PKCE flow every hour. Same key / iss / aud as access tokens; the
   * ``typ`` claim is the only thing distinguishing them, and
   * ``verifyAccessToken`` rejects ``typ="refresh"`` so a refresh token can
   * never be used as an access token at the ``/mcp`` resource.
   */
  async issueRefreshToken(sub: string, expiresInSeconds = 2592000): Promise<string> {
    if (!this.privateKey) throw new Error('JWTIssuer not initialized')
    return new jose.SignJWT({ sub, typ: 'refresh' })
      .setProtectedHeader({ alg: 'RS256', kid: this.kid })
      .setIssuer(this.serverName)
      .setAudience(this.serverName)
      .setIssuedAt()
      .setExpirationTime(`${expiresInSeconds}s`)
      .sign(this.privateKey)
  }

  /**
   * Verify a JWT access token and return its payload. Throws on failure
   * (bad signature, wrong issuer/audience, expired) — the same jose errors
   * existing callers already catch. Additionally rejects tokens whose
   * ``typ`` claim is ``"refresh"`` (throwing ``jose.errors.JWTClaimValidationFailed``)
   * so a refresh token cannot be replayed as an access token. Tokens with
   * ``typ="access"`` OR a missing ``typ`` claim are accepted (the latter
   * keeps already-issued pre-refresh-support tokens valid).
   */
  async verifyAccessToken(token: string): Promise<jose.JWTPayload> {
    if (!this.publicKey) throw new Error('JWTIssuer not initialized')
    const { payload } = await jose.jwtVerify(token, this.publicKey, {
      issuer: this.serverName,
      audience: this.serverName
    })
    if (payload.typ === 'refresh') {
      throw new jose.errors.JWTClaimValidationFailed('Refresh token cannot be used as an access token', payload, 'typ')
    }
    return payload
  }

  /**
   * Verify a JWT refresh token and return its payload. Same key / audience /
   * issuer checks as ``verifyAccessToken`` and throws the same jose errors on
   * failure. Additionally asserts ``typ=="refresh"`` (throwing
   * ``jose.errors.JWTClaimValidationFailed`` otherwise) so an access token
   * can never be exchanged at the refresh grant. ``JWTClaimValidationFailed``
   * extends ``jose.errors.JOSEError``, so callers' existing ``catch`` clauses
   * around ``verifyAccessToken`` already catch it.
   */
  async verifyRefreshToken(token: string): Promise<jose.JWTPayload> {
    if (!this.publicKey) throw new Error('JWTIssuer not initialized')
    const { payload } = await jose.jwtVerify(token, this.publicKey, {
      issuer: this.serverName,
      audience: this.serverName
    })
    if (payload.typ !== 'refresh') {
      throw new jose.errors.JWTClaimValidationFailed('Token is not a refresh token', payload, 'typ')
    }
    return payload
  }
}
