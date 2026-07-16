export interface ConfigField {
  key: string
  label: string
  type: 'text' | 'password' | 'number' | 'tel' | 'url' | 'email' | 'select'
  placeholder?: string
  helpUrl?: string
  helpText?: string
  default?: string
  choices?: string[]
  required?: boolean
  validation?: string
}

export interface ConfigMode {
  id: string
  label: string
  description: string
  fields: ConfigField[]
}

export interface OAuthRoute {
  match: string[]
  action: 'oauth2_device_code'
  message: string
  oauthConfig: Record<string, unknown>
}

export interface CredentialsRoute {
  match: string[]
  action: 'credentials'
  fields: ConfigField[]
}

export interface DynamicFlow {
  entryField: ConfigField
  routes: (OAuthRoute | CredentialsRoute)[]
}

/**
 * A credential-form tab (schema-level `tabs` capability). Each tab is a
 * mutually-exclusive credential mode; only the active tab's fields submit.
 */
export interface TabGroup {
  id: string
  label: string
  fields: ConfigField[]
}

/**
 * A repeatable field group (schema-level `cardGroup` capability). Renders
 * Add/Remove cards, each cloning `fields`; submitted as a JSON array under
 * `key` (e.g. `{ accounts: [{...}, {...}] }`).
 */
export interface CardGroup {
  key: string
  fields: ConfigField[]
  itemLabel?: string
  heading?: string
  addButtonLabel?: string
  minItems?: number
  titleField?: string
}

export interface RelayConfigSchema {
  server: string
  displayName: string
  modes?: ConfigMode[]
  fields?: ConfigField[]
  optional?: ConfigField[]
  dynamicFlow?: DynamicFlow
  tabs?: TabGroup[]
  cardGroup?: CardGroup
}
