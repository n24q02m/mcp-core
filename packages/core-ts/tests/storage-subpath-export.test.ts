import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import * as storage from '../src/storage/index.js'

// The `@n24q02m/mcp-core/storage` subpath must resolve to the storage barrel, not
// the narrow resolver module. Downstream CF deployments (better-notion, email)
// import CfKvBackend / PerPluginStore / backendFromEnv from this subpath; pointing
// it at resolver.js (which only exports resolveConfig) silently strips those
// symbols at the published-package boundary while source builds stay green.
describe('storage subpath export (./storage)', () => {
  const pkg = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf-8')) as {
    exports: Record<string, { import: string; types: string }>
  }

  it('points the ./storage subpath at the barrel index, not resolver', () => {
    expect(pkg.exports['./storage'].import).toBe('./build/storage/index.js')
    expect(pkg.exports['./storage'].types).toBe('./build/storage/index.d.ts')
  })

  it('the barrel exposes the CF storage seam used by downstream servers', () => {
    expect(typeof storage.CfKvBackend).toBe('function')
    expect(typeof storage.PerPluginStore).toBe('function')
    expect(typeof storage.backendFromEnv).toBe('function')
  })

  it('the barrel still re-exports resolveConfig (backward compatibility)', () => {
    // Existing consumers import { resolveConfig } from '@n24q02m/mcp-core/storage';
    // repointing the subpath must not break them.
    expect(typeof storage.resolveConfig).toBe('function')
  })
})
