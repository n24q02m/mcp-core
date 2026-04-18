// Local OAuth 2.1 Authorization Server (single-user, 127.0.0.1) +
// Delegated OAuth (upstream redirect / device code) for remote multi-user.
export {
  authorizationServerMetadata,
  type CapabilityInfo,
  type ConfigField,
  type CredentialsCallback,
  createDelegatedOAuthApp,
  createLocalOAuthApp,
  type DelegatedOAuthAppOptions,
  type DelegatedOAuthAppResult,
  type FlowType,
  type LocalOAuthAppOptions,
  type LocalOAuthAppResult,
  type NextStep,
  type OAuthTokens,
  protectedResourceMetadata,
  type RelayConfigSchema,
  type RenderOptions,
  renderCredentialForm,
  type StepCallback,
  type TokenCallback,
  type UpstreamOAuthConfig
} from './auth/index.js'
export * from './crypto/index.js'
// OAuth 2.1 multi-user infrastructure (HTTP mode)
export { JWTIssuer } from './oauth/jwt-issuer.js'
export {
  InMemoryAuthCache,
  type IOAuthSessionCache,
  OAuthProvider,
  type OAuthProviderOptions,
  type PreAuthSession
} from './oauth/provider.js'
export { type IUserCredentialStore, SqliteUserStore } from './oauth/user-store.js'
export { tryOpenBrowser } from './relay/browser.js'
export {
  createSession,
  generatePassphrase,
  pollForResponses,
  pollForResult,
  type RelaySession,
  sendMessage
} from './relay/client.js'
export type * from './schema/types.js'
export {
  deleteConfig,
  exportConfig,
  importConfig,
  listConfigs,
  readConfig,
  scheduleReloadExit,
  writeConfig
} from './storage/config-file.js'
export { clearMode, getMode, type ServerMode, setLocalMode } from './storage/mode.js'
export * from './storage/resolver.js'
export {
  acquireSessionLock,
  releaseSessionLock,
  type SessionInfo,
  writeSessionLock
} from './storage/session-lock.js'
// Local MCP server entry point (OAuth AS + /mcp transport on 127.0.0.1)
export {
  type LocalServerHandle,
  type RunLocalServerOptions,
  runLocalServer
} from './transport/local-server.js'
