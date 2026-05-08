/**
 * Server mode management: local-only vs relay-configured.
 *
 * Persists user's choice to skip relay permanently by storing a mode marker
 * in the existing config.enc encrypted storage.
 */

import { deleteConfig, readConfig, writeConfig } from './config-file.js'

const MODE_KEY = '_mode'
const LOCAL_MODE_VALUE = 'local'

export type ServerMode = 'local' | 'configured' | null

/**
 * Mark server as local-only (user explicitly skipped relay).
 * Writes {"_mode": "local"} to config.enc[serverName].
 */
export async function setLocalMode(serverName: string): Promise<void> {
  await writeConfig(serverName, { [MODE_KEY]: LOCAL_MODE_VALUE })
}

/**
 * Get server mode.
 * Returns "local" if local mode set, "configured" if has other keys, null if empty.
 */
export async function getMode(serverName: string): Promise<ServerMode> {
  const config = await readConfig(serverName)
  if (config === null) {
    return null
  }

  if (config[MODE_KEY] === LOCAL_MODE_VALUE) {
    return 'local'
  }

  // Has keys other than _mode -> configured
  const nonModeKeys = Object.keys(config).filter((k) => k !== MODE_KEY)
  if (nonModeKeys.length > 0) {
    return 'configured'
  }

  return null
}

/**
 * Remove mode marker (allows relay to trigger again).
 * Deletes the server's config entry entirely.
 */
export async function clearMode(serverName: string): Promise<void> {
  await deleteConfig(serverName)
}
