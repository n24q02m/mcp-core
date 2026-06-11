/**
 * OAuth 2.1 Bearer token validation middleware for Streamable HTTP.
 *
 * Validates `Authorization: Bearer <token>` headers on incoming requests
 * against a `JWTIssuer`. On missing or invalid token it writes a 401
 * with `WWW-Authenticate: Bearer resource_metadata="..."` per RFC 6750 +
 * RFC 9728 (OAuth 2.1 protected resource metadata discovery).
 *
 * Success attaches the validated claims to `(req as any).user` so
 * downstream handlers can read the subject without re-validating.
 */

import type { IncomingMessage, ServerResponse } from 'node:http'

import type { JWTIssuer } from '../oauth/jwt-issuer.js'

export interface OAuthMiddlewareOptions {
  jwtIssuer: JWTIssuer
  resourceMetadataUrl: string
  /**
   * When `true`, skip Bearer token validation and attach an anonymous user
   * claim. Intended for deployments behind an external auth boundary
   * (reverse proxy, API gateway like agentgateway/Zitadel) where the caller
   * has already verified identity. Logs a warning on construction; the
   * deployer is responsible for ensuring upstream auth is in place.
   */
  authDisabled?: boolean
}

export interface AuthenticatedRequest extends IncomingMessage {
  user?: Record<string, unknown>
}

function writeChallenge(res: ServerResponse, resourceMetadataUrl: string, error?: string): void {
  const params = [`resource_metadata="${resourceMetadataUrl}"`]
  if (error) params.push(`error="${error}"`)
  res.writeHead(401, {
    'WWW-Authenticate': `Bearer ${params.join(', ')}`,
    'Content-Type': 'application/json'
  })
  res.end(
    JSON.stringify({
      error: error ?? 'unauthorized',
      error_description: error ? 'The access token is missing or invalid' : 'Authentication required'
    })
  )
}

export function extractBearerToken(authHeader: string | undefined): string | null {
  if (!authHeader) return null

  // Fast path for strictly "Bearer " or "bearer " (exact case & single space)
  if (authHeader.startsWith('Bearer ') || authHeader.startsWith('bearer ')) {
    const token = authHeader.substring(7).trim()
    return token.length > 0 ? token : null
  }

  // Fallback for tricky cases (mixed case, leading whitespace, etc.)
  const trimmed = authHeader.trim()
  if (trimmed.length <= 6) return null

  const prefix = trimmed.substring(0, 6)
  if (prefix.toLowerCase() !== 'bearer') return null

  const char6 = trimmed.charCodeAt(6)
  // Check if character 6 is whitespace (space=32, tab=9, newline=10, return=13)
  if (char6 !== 32 && char6 !== 9 && char6 !== 10 && char6 !== 13) return null

  const token = trimmed.substring(7).trim()
  return token.length > 0 ? token : null
}

export class OAuthMiddleware {
  private readonly _issuer: JWTIssuer
  private readonly _resourceMetadataUrl: string
  private readonly _authDisabled: boolean

  constructor(options: OAuthMiddlewareOptions) {
    this._issuer = options.jwtIssuer
    this._resourceMetadataUrl = options.resourceMetadataUrl
    this._authDisabled = options.authDisabled === true
    if (this._authDisabled) {
      console.warn(
        '[mcp-core OAuthMiddleware] auth_disabled=true — Bearer token validation skipped. ' +
          'Caller must enforce authentication at the network boundary (e.g. reverse proxy, API gateway).'
      )
    }
  }

  /**
   * Validate the request. Returns `true` if the request should proceed
   * (and attaches `req.user` on success). Returns `false` if the
   * middleware has already written a 401 response.
   *
   * When constructed with `authDisabled: true`, this short-circuits to
   * `true` and attaches `{ sub: 'anonymous', anonymous: true }` to `req.user`.
   */
  async validate(req: AuthenticatedRequest, res: ServerResponse): Promise<boolean> {
    if (this._authDisabled) {
      req.user = { sub: 'anonymous', anonymous: true }
      return true
    }
    const token = extractBearerToken(req.headers.authorization)
    if (!token) {
      writeChallenge(res, this._resourceMetadataUrl)
      return false
    }
    try {
      const claims = await this._issuer.verifyAccessToken(token)
      req.user = claims
      return true
    } catch {
      writeChallenge(res, this._resourceMetadataUrl, 'invalid_token')
      return false
    }
  }
}
