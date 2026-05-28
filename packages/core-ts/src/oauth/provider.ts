/**
 * OAuth 2.1 Provider logic for TypeScript MCP servers.
 *
 * Implements the "MCP Server as Authorization Server" pattern.
 * The MCP Server issues JWTs, processes PKCE verification,
 * and uses the Relay Server purely as a UI consent transport.
 */

import { createSession, pollForResult, type RelaySession } from '../relay/client.js'
import type { RelayConfigSchema } from '../schema/types.js'
import { InMemoryAuthCache, type IOAuthSessionCache, type PreAuthSession } from './cache.js'
import type { JWTIssuer } from './jwt-issuer.js'
import { verifyPKCE } from './pkce.js'

export {
  InMemoryAuthCache,
  type IOAuthSessionCache,
  type PreAuthSession
} from './cache.js'

export interface OAuthProviderOptions {
  serverName: string
  relayBaseUrl: string
  relaySchema: RelayConfigSchema
  jwtIssuer: JWTIssuer
  cache?: IOAuthSessionCache
}

export class OAuthProvider {
  private serverName: string
  private relayBaseUrl: string
  private relaySchema: RelayConfigSchema
  private jwtIssuer: JWTIssuer
  private cache: IOAuthSessionCache

  constructor(options: OAuthProviderOptions) {
    this.serverName = options.serverName
    this.relayBaseUrl = options.relayBaseUrl
    this.relaySchema = options.relaySchema
    this.jwtIssuer = options.jwtIssuer
    this.cache = options.cache ?? new InMemoryAuthCache()
  }

  /**
   * Create a relay session and return the URL to redirect the user to.
   */
  async createAuthorizeRedirect(
    clientId: string,
    redirectUri: string,
    state: string,
    codeChallenge: string,
    codeChallengeMethod = 'S256'
  ): Promise<string> {
    const session = await createSession(this.relayBaseUrl, this.serverName, this.relaySchema)

    // Export private key for later credential retrieval
    const privateJwk = await crypto.subtle.exportKey('jwk', session.keyPair.privateKey)

    const preAuth: PreAuthSession = {
      sessionId: session.sessionId,
      clientId,
      redirectUri,
      state,
      codeChallenge,
      codeChallengeMethod,
      keyPairJwk: privateJwk,
      passphrase: session.passphrase,
      expiresAt: Math.floor(Date.now() / 1000) + 600 // 10 minutes
    }
    this.cache.save(preAuth)
    return session.relayUrl
  }

  /**
   * Exchange the authorization code (relay session ID) for an access_token.
   * PKCE verification is performed.
   *
   * @param code The authorization code from the client.
   * @param codeVerifier The PKCE code verifier.
   * @param userIdExtractor Function to derive a unique user_id from the credentials.
   * @returns Tuple of [access_token, credentials]
   */
  async exchangeCode(
    code: string,
    codeVerifier: string,
    userIdExtractor: (credentials: Record<string, string>) => string
  ): Promise<{ accessToken: string; credentials: Record<string, string> }> {
    const preAuth = this.cache.getAndDelete(code)
    if (!preAuth) throw new Error('invalid_grant: Expired or invalid code')

    // Verify PKCE
    verifyPKCE(codeVerifier, preAuth.codeChallenge, preAuth.codeChallengeMethod)

    // Reconstruct relay session
    const reconstructedSession = await this.reconstructRelaySession(preAuth)

    // Poll for credentials (short timeout — form already submitted)
    const credentials = await pollForResult(this.relayBaseUrl, reconstructedSession, 1000, 10_000)

    // Extract unique user_id
    const userId = userIdExtractor(credentials)
    if (!userId) throw new Error('server_error: Unable to extract user_id from credentials')

    // Issue access token
    const accessToken = await this.jwtIssuer.issueAccessToken(userId)
    return { accessToken, credentials }
  }

  /**
   * Reconstruct relay session from pre-auth session.
   */
  private async reconstructRelaySession(preAuth: PreAuthSession): Promise<RelaySession> {
    // Reconstruct key pair to decrypt relay credentials
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      preAuth.keyPairJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    )
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      { ...preAuth.keyPairJwk, d: undefined },
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    )
    return {
      sessionId: preAuth.sessionId,
      keyPair: { privateKey, publicKey },
      passphrase: preAuth.passphrase,
      relayUrl: ''
    }
  }

  /**
   * Get RFC 8414 Authorization Server Metadata.
   */
  getMetadata(baseUrl: string): Record<string, unknown> {
    return {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      jwks_uri: `${baseUrl}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256', 'plain'],
      token_endpoint_auth_methods_supported: ['none']
    }
  }
}
