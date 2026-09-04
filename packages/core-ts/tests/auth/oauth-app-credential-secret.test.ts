/**
 * OAuth-app fallback issuer secret selection (mirrors core-py).
 * MCP_JWT_SIGNING_SECRET takes precedence so operators can revoke OAuth tokens
 * without rotating CREDENTIAL_SECRET, which also encrypts per-sub vaults and
 * derives stable subjects. Existing deployments retain the
 * CREDENTIAL_SECRET fallback and cross-language signing-key parity.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import type { RelayConfigSchema } from '../../src/auth/credential-form.js'
import { createDelegatedOAuthApp, type UpstreamOAuthConfig } from '../../src/auth/delegated-oauth-app.js'
import { createLocalOAuthApp } from '../../src/auth/local-oauth-app.js'

const SECRET = 'test-credential-secret-value'
const PARITY_KID = 'r71l8IICMLZykZU5'

const SCHEMA: RelayConfigSchema = {
  server: 'wet-mcp',
  displayName: 'Wet',
  description: 'parity test server',
  fields: []
}

const UPSTREAM: UpstreamOAuthConfig = {
  tokenUrl: 'https://example.test/token',
  clientId: 'upstream-client',
  scopes: ['read'],
  authorizeUrl: 'https://example.test/authorize'
}

describe('OAuth-app factory fallback issuer secret selection', () => {
  let originalCredential: string | undefined
  let originalSigning: string | undefined

  beforeEach(() => {
    originalCredential = process.env.CREDENTIAL_SECRET
    originalSigning = process.env.MCP_JWT_SIGNING_SECRET
    delete process.env.MCP_JWT_SIGNING_SECRET
  })

  afterEach(() => {
    if (originalCredential === undefined) delete process.env.CREDENTIAL_SECRET
    else process.env.CREDENTIAL_SECRET = originalCredential
    if (originalSigning === undefined) delete process.env.MCP_JWT_SIGNING_SECRET
    else process.env.MCP_JWT_SIGNING_SECRET = originalSigning
  })

  it('local factory derives EdDSA from CREDENTIAL_SECRET when no issuer injected', async () => {
    process.env.CREDENTIAL_SECRET = SECRET
    const { jwtIssuer } = await createLocalOAuthApp({ serverName: 'wet-mcp', relaySchema: SCHEMA })
    expect(jwtIssuer.alg).toBe('EdDSA')
    const jwks = await jwtIssuer.getJwks()
    expect(jwks.keys[0].kty).toBe('OKP')
    expect(jwks.keys[0].kid).toBe(PARITY_KID)
  })

  it('delegated factory derives EdDSA from CREDENTIAL_SECRET when no issuer injected', async () => {
    process.env.CREDENTIAL_SECRET = SECRET
    const result = await createDelegatedOAuthApp({
      serverName: 'wet-mcp',
      flow: 'redirect',
      upstream: UPSTREAM,
      onTokenReceived: () => undefined
    })
    expect(result.jwtIssuer.alg).toBe('EdDSA')
    const jwks = await result.jwtIssuer.getJwks()
    expect(jwks.keys[0].kty).toBe('OKP')
    expect(jwks.keys[0].kid).toBe(PARITY_KID)
    await result.shutdown()
  })

  it('prefers a domain-separated JWT signing secret in both factories', async () => {
    process.env.CREDENTIAL_SECRET = SECRET
    process.env.MCP_JWT_SIGNING_SECRET = 'jwt-signing-secret-a'
    const local = await createLocalOAuthApp({ serverName: 'wet-mcp', relaySchema: SCHEMA })
    const oldToken = await local.jwtIssuer.issueAccessToken('existing-sub')

    process.env.MCP_JWT_SIGNING_SECRET = 'jwt-signing-secret-b'
    const delegated = await createDelegatedOAuthApp({
      serverName: 'wet-mcp',
      flow: 'redirect',
      upstream: UPSTREAM,
      onTokenReceived: () => undefined
    })

    const oldJwks = await local.jwtIssuer.getJwks()
    const newJwks = await delegated.jwtIssuer.getJwks()
    expect(oldJwks.keys[0].kid).not.toBe(newJwks.keys[0].kid)
    await expect(delegated.jwtIssuer.verifyAccessToken(oldToken)).rejects.toThrow()
    await delegated.shutdown()
  })
})
