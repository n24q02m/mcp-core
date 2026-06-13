/**
 * Factory-fallback parity (mirrors Python test_oauth_app_credential_secret.py):
 * when no JWTIssuer is injected, createLocalOAuthApp / createDelegatedOAuthApp
 * must build one in EdDSA mode if CREDENTIAL_SECRET is set, so the derived
 * stable signing key is used even via the factory's own fallback issuer.
 *
 * serverName='wet-mcp' + the canonical secret reproduce the cross-language
 * thumbprint kid from crypto-vectors.json. EdDSA mode derives the key and
 * never writes PEM files.
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

describe('OAuth-app factory fallback issuer mode (CREDENTIAL_SECRET)', () => {
  let original: string | undefined

  beforeEach(() => {
    original = process.env.CREDENTIAL_SECRET
  })

  afterEach(() => {
    if (original === undefined) delete process.env.CREDENTIAL_SECRET
    else process.env.CREDENTIAL_SECRET = original
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
})
