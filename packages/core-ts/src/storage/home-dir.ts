/**
 * Shared home-directory resolution with a testing override.
 *
 * Extracted out of per-plugin-store.ts so that both PerPluginStore and the
 * LocalFsBackend in backends.ts can honor the same override without a circular
 * value import (per-plugin-store imports backendFromEnv from backends).
 */

import { homedir } from 'node:os'

// Module-level override for testing.
let homeDirOverride: string | null = null

/** Override the home directory used by storage modules. Pass null to reset. */
export function setHomeDirForTesting(dir: string | null): void {
  homeDirOverride = dir
}

export function getHomeDir(): string {
  return homeDirOverride ?? homedir()
}
