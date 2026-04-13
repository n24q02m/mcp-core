/** OAuth 2.1 well-known metadata generators (RFC 8414 + RFC 9728). */

export function authorizationServerMetadata(issuerUrl: string): Record<string, unknown> {
  return {
    issuer: issuerUrl,
    authorization_endpoint: `${issuerUrl}/authorize`,
    token_endpoint: `${issuerUrl}/token`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none']
  }
}

export function protectedResourceMetadata(resource: string, authorizationServers: string[]): Record<string, unknown> {
  return {
    resource,
    authorization_servers: authorizationServers,
    bearer_methods_supported: ['header']
  }
}
