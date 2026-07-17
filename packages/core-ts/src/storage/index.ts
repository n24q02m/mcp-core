export { atomicWriteFile } from './atomic-write.js'
export {
  backendFromEnv,
  CfKvBackend,
  type CredentialBackend,
  InMemoryBackend,
  LocalFsBackend
} from './backends.js'
export { exportConfig, importConfig, listConfigs, setConfigPath } from './config-file.js'
// Single-user credential read/write/delete route through the unified
// per-plugin store (with legacy config.enc read fallback), so downstream
// servers and the CLI built-ins converge on the same on-disk location.
export {
  deleteStoredConfig as deleteConfig,
  readStoredConfig as readConfig,
  writeStoredConfig as writeConfig
} from './credential-store.js'
export { decryptData, deriveFileKey, derivePassphraseKey, encryptData } from './encryption.js'
export { getMachineId, getUsername } from './machine-id.js'
export { clearMode, getMode, type ServerMode, setLocalMode } from './mode.js'
export { credPath, PerPluginStore, setHomeDirForTesting } from './per-plugin-store.js'
export { type ConfigSource, type ResolvedConfig, resolveConfig } from './resolver.js'
export {
  acquireSessionLock,
  releaseSessionLock,
  type SessionInfo,
  setLockDir,
  writeSessionLock
} from './session-lock.js'
