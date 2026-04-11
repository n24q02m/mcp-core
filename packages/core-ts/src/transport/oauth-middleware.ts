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

function extractBearerToken(authHeader: string | undefined): string | null {
  if (!authHeader) return null
  const trimmed = authHeader.trim()
  const match = trimmed.match(/^Bearer\s+(.+)$/i)
  if (!match) return null
  const token = match[1]?.trim() ?? ''
  return token.length > 0 ? token : null
}

export class OAuthMiddleware {
  private readonly _issuer: JWTIssuer
  private readonly _resourceMetadataUrl: string

  constructor(options: OAuthMiddlewareOptions) {
    this._issuer = options.jwtIssuer
    this._resourceMetadataUrl = options.resourceMetadataUrl
  }

  /**
   * Validate the request. Returns `true` if the request should proceed
   * (and attaches `req.user` on success). Returns `false` if the
   * middleware has already written a 401 response.
   */
  async validate(req: AuthenticatedRequest, res: ServerResponse): Promise<boolean> {
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
