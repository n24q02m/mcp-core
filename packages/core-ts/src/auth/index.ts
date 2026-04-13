/**
 * Public exports for the ``auth`` subpath.
 *
 * Intentionally does NOT export ``router`` (internal HTTP glue).
 */

export {
  type CapabilityInfo,
  type ConfigField,
  type RelayConfigSchema,
  type RenderOptions,
  renderCredentialForm
} from './credential-form.js'
export {
  createDelegatedOAuthApp,
  type DelegatedOAuthAppOptions,
  type DelegatedOAuthAppResult,
  type FlowType,
  type OAuthTokens,
  type TokenCallback,
  type UpstreamOAuthConfig
} from './delegated-oauth-app.js'
export {
  type CredentialsCallback,
  createLocalOAuthApp,
  type LocalOAuthAppOptions,
  type LocalOAuthAppResult,
  type NextStep,
  type StepCallback
} from './local-oauth-app.js'
export { authorizationServerMetadata, protectedResourceMetadata } from './well-known.js'
