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

  /** Must call before using issuer — loads or generates RSA keys. */
  async init(): Promise<void> {
    if (this._initialized) return
    mkdirSync(this.keysDir, { recursive: true, mode: 0o700 })

    if (existsSync(this.privateKeyPath) && existsSync(this.publicKeyPath)) {
      const privatePem = readFileSync(this.privateKeyPath, 'utf-8')
      const publicPem = readFileSync(this.publicKeyPath, 'utf-8')
      this.privateKey = await jose.importPKCS8(privatePem, 'RS256')
      this.publicKey = await jose.importSPKI(publicPem, 'RS256')
    } else {
      const { publicKey, privateKey } = await jose.generateKeyPair('RS256', {
        modulusLength: 2048,
        extractable: true
      })
      this.privateKey = privateKey
      this.publicKey = publicKey

      const privatePem = await jose.exportPKCS8(privateKey)
      const publicPem = await jose.exportSPKI(publicKey)

      writeFileSync(this.privateKeyPath, privatePem, { mode: 0o600 })
      writeFileSync(this.publicKeyPath, publicPem, { mode: 0o644 })
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

  /** Issue an RS256 JWT access token. */
  async issueAccessToken(sub: string, expiresInSeconds = 3600): Promise<string> {
    if (!this.privateKey) throw new Error('JWTIssuer not initialized')
    return new jose.SignJWT({ sub })
      .setProtectedHeader({ alg: 'RS256', kid: this.kid })
      .setIssuer(this.serverName)
      .setAudience(this.serverName)
      .setIssuedAt()
      .setExpirationTime(`${expiresInSeconds}s`)
      .sign(this.privateKey)
  }

  /** Verify JWT and return payload. Throws on failure. */
  async verifyAccessToken(token: string): Promise<jose.JWTPayload> {
    if (!this.publicKey) throw new Error('JWTIssuer not initialized')
    const { payload } = await jose.jwtVerify(token, this.publicKey, {
      issuer: this.serverName,
      audience: this.serverName
    })
    return payload
  }
}
