/**
 * Regression: bridge daemon-spawn must strip stdio-mode env vars.
 *
 * Without env strip, the detached daemon child inherits MCP_TRANSPORT=stdio
 * (or TRANSPORT_MODE=stdio) from the bridge process, re-enters runSmartStdioProxy
 * in its own main(), and fork-bombs spawning daemons recursively until OS
 * exhausts handles. Mirrors core-py `tests/transport/test_smart_stdio.py`
 * coverage of `_spawn_daemon` env strip.
 *
 * Source-level invariant test: the env-clean expression in smart-stdio.ts
 * must filter out both stdio-mode keys before merging with options.env.
 */

import { describe, expect, it } from 'vitest'

describe('runSmartStdioProxy daemon spawn env strip (regression for fork-bomb spam)', () => {
  it('removes MCP_TRANSPORT and TRANSPORT_MODE keys from inherited env before passing to detached daemon', async () => {
    const fs = await import('node:fs')
    const path = await import('node:path')
    const url = await import('node:url')
    const here = url.fileURLToPath(import.meta.url)
    const source = fs.readFileSync(path.resolve(path.dirname(here), '../../src/transport/smart-stdio.ts'), 'utf-8')

    // The env-clean expression must filter both stdio markers explicitly.
    // Match either `k !== 'MCP_TRANSPORT' && k !== 'TRANSPORT_MODE'` or
    // a Set-based check `!STDIO_ENV_KEYS.has(k)` with the keys defined nearby.
    const expressionPattern = /k\s*!==\s*['"]MCP_TRANSPORT['"]\s*&&\s*k\s*!==\s*['"]TRANSPORT_MODE['"]/
    const setPattern = /['"]MCP_TRANSPORT['"][\s\S]{0,40}['"]TRANSPORT_MODE['"]/
    expect(expressionPattern.test(source) || setPattern.test(source)).toBe(true)
  })

  it('passes the cleaned env to the spawned child (not raw process.env)', async () => {
    const fs = await import('node:fs')
    const path = await import('node:path')
    const url = await import('node:url')
    const here = url.fileURLToPath(import.meta.url)
    const source = fs.readFileSync(path.resolve(path.dirname(here), '../../src/transport/smart-stdio.ts'), 'utf-8')

    // The spawn invocation in runSmartStdioProxy should use cleanEnv (or
    // an equivalent locally-bound clean env), not raw process.env.
    // Find the bridge daemon spawn block — the one inside `if (!daemon)`.
    const bridgeSpawnBlock = source.match(/if\s*\(!daemon\)\s*\{[\s\S]*?const\s+child\s*=\s*spawn\([\s\S]*?\}\s*\)/)
    expect(bridgeSpawnBlock).not.toBeNull()
    const spawnSnippet = bridgeSpawnBlock![0]

    // Must not pass raw `...process.env` directly without the filter.
    // The filtered version uses Object.fromEntries / .filter / clean env name.
    expect(spawnSnippet).toMatch(/cleanEnv|cleanedEnv|filteredEnv|stripStdio/)
  })
})
