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

export interface RelayConfigSchema {
  server: string
  displayName: string
  modes?: ConfigMode[]
  fields?: ConfigField[]
  optional?: ConfigField[]
  dynamicFlow?: DynamicFlow
}
