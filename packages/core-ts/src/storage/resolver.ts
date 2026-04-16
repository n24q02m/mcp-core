import { readConfig } from './config-file.js'

export type ConfigSource = 'env' | 'file' | 'defaults' | null

export interface ResolvedConfig {
  config: Record<string, string> | null
  source: ConfigSource
}

export async function resolveConfig(
  serverName: string,
  requiredFields: string[],
  defaults?: Record<string, string>
): Promise<ResolvedConfig> {
  // 1. Check env vars -- if ALL required fields present as env vars, use them
  const envConfig: Record<string, string> = {}
  let allEnvPresent = requiredFields.length > 0
  const serverEnvPrefix = serverName.toUpperCase().replace(/-/g, '_')
  for (const field of requiredFields) {
    const envKey = `MCP_${serverEnvPrefix}_${field.toUpperCase().replace(/-/g, '_')}`
    const value = process.env[envKey]
    if (value !== undefined && value !== '') {
      envConfig[field] = value
    } else {
      allEnvPresent = false
    }
  }
  if (allEnvPresent) {
    return { config: envConfig, source: 'env' }
  }

  // 2. Check config file
  const fileConfig = await readConfig(serverName)
  if (fileConfig) {
    const hasAllRequired = requiredFields.every((f) => f in fileConfig && fileConfig[f] !== '')
    if (hasAllRequired) {
      return { config: fileConfig, source: 'file' }
    }
  }

  // 3. Check defaults
  if (defaults) {
    const hasAllRequired = requiredFields.every((f) => f in defaults && defaults[f] !== '')
    if (hasAllRequired) {
      return { config: { ...defaults }, source: 'defaults' }
    }
  }

  // 4. Nothing found -- trigger relay setup
  return { config: null, source: null }
}
