import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  LocalFsBackend,
  PerPluginStore,
  setConfigPath,
  setHomeDirForTesting,
  setLockDir,
  writeSessionLock
} from '../storage/index.js'
import { buildCli } from './build-cli.js'

const SERVER = 'w51-test'

let tmp: string
let logs: string[]
let errs: string[]

function capture(): void {
  logs = []
  errs = []
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    logs.push(args.join(' '))
  })
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    errs.push(args.join(' '))
  })
}

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'w51-'))
  setHomeDirForTesting(tmp)
  setLockDir(join(tmp, 'locks'))
  setConfigPath(join(tmp, 'config.enc'))
  // Never hijack the real browser during `relay open` tests.
  process.env.MCP_NO_BROWSER = '1'
  capture()
})

afterEach(() => {
  vi.restoreAllMocks()
  setHomeDirForTesting(null)
  setLockDir(null)
  setConfigPath(null)
  rmSync(tmp, { recursive: true, force: true })
})

describe('buildCli — serve dispatch', () => {
  it('runs the server with an empty argv on bare invocation', async () => {
    const seen: string[][] = []
    const run = buildCli(SERVER, {
      serve: (argv) => {
        seen.push(argv)
      }
    })
    const rc = await run([])
    expect(seen).toEqual([[]])
    expect(rc).toBe(0)
  })

  it('passes flag-prefixed argv through to serve byte-for-byte', async () => {
    const seen: string[][] = []
    const run = buildCli(SERVER, {
      serve: (argv) => {
        seen.push(argv)
      }
    })
    const rc = await run(['--http', '8080'])
    expect(seen).toEqual([['--http', '8080']])
    expect(rc).toBe(0)
  })

  it('propagates a numeric return code from serve', async () => {
    const run = buildCli(SERVER, { serve: () => 3 })
    expect(await run([])).toBe(3)
  })
})

describe('buildCli — help and version', () => {
  it('prints help on -h without touching serve', async () => {
    let served = false
    const run = buildCli(SERVER, {
      serve: () => {
        served = true
      }
    })
    const rc = await run(['-h'])
    expect(rc).toBe(0)
    expect(served).toBe(false)
    expect(logs[0]).toBe(`usage: ${SERVER} [-h] [--version] [<subcommand> ...]`)
    expect(logs.join('\n')).toContain('subcommands: config, doctor, relay')
  })

  it('prints help on --help', async () => {
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['--help'])).toBe(0)
    expect(logs.join('\n')).toContain('passed through to the MCP server')
  })

  it('lists extra subcommands sorted in help', async () => {
    const run = buildCli(SERVER, { serve: () => 0, extra: { auth: () => 0 } })
    await run(['-h'])
    expect(logs.join('\n')).toContain('subcommands: auth, config, doctor, relay')
  })

  it('prints "<name> <version>" on --version when version is set', async () => {
    const run = buildCli(SERVER, { serve: () => 0, version: '1.2.3' })
    expect(await run(['--version'])).toBe(0)
    expect(logs).toEqual([`${SERVER} 1.2.3`])
  })

  it('prints version on -V', async () => {
    const run = buildCli(SERVER, { serve: () => 0, version: '1.2.3' })
    expect(await run(['-V'])).toBe(0)
    expect(logs).toEqual([`${SERVER} 1.2.3`])
  })

  it('falls through --version to serve when version is unset', async () => {
    const seen: string[][] = []
    const run = buildCli(SERVER, {
      serve: (argv) => {
        seen.push(argv)
      }
    })
    expect(await run(['--version'])).toBe(0)
    expect(seen).toEqual([['--version']])
  })
})

describe('buildCli — unknown subcommand', () => {
  it('reports an unknown subcommand on stderr with rc 2', async () => {
    const run = buildCli(SERVER, { serve: () => 0 })
    const rc = await run(['bogus'])
    expect(rc).toBe(2)
    expect(errs.join('\n')).toContain(`${SERVER}: unknown subcommand 'bogus'`)
    expect(errs.join('\n')).toContain('expected one of: config, doctor, relay')
  })
})

describe('buildCli — config subcommand', () => {
  it('reports not configured', async () => {
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['config', 'status'])).toBe(0)
    expect(logs[0]).toBe(`${SERVER}: not configured`)
  })

  it('reports configured after a payload is saved', async () => {
    await new PerPluginStore(SERVER).save({ token: 'secret' })
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['config', 'status'])).toBe(0)
    expect(logs[0]).toBe(`${SERVER}: configured (source: file)`)
    // A credential value is never printed by a built-in.
    expect(logs.join('\n')).not.toContain('secret')
  })

  it('reports a corrupt (undecryptable) config with rc 1', async () => {
    await new LocalFsBackend().put(`${SERVER}/config`, Buffer.from('too-short'))
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['config', 'status'])).toBe(1)
    expect(errs.join('\n')).toContain('config is corrupt')
  })

  it('deletes config with --yes', async () => {
    const store = new PerPluginStore(SERVER)
    await store.save({ token: 'secret' })
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['config', 'delete', '--yes'])).toBe(0)
    expect(logs[0]).toBe(`${SERVER}: config deleted`)
    expect(await store.load()).toBeNull()
  })

  it('refuses to delete without --yes in non-interactive mode', async () => {
    await new PerPluginStore(SERVER).save({ token: 'secret' })
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['config', 'delete'])).toBe(1)
    expect(errs.join('\n')).toContain('refusing to delete without --yes')
  })

  it('returns rc 2 on a missing or invalid config action', async () => {
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['config'])).toBe(2)
    expect(await run(['config', 'bogus'])).toBe(2)
  })
})

describe('buildCli — relay subcommand', () => {
  it('reports no active session on status with rc 1', async () => {
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['relay', 'status'])).toBe(1)
    expect(errs.join('\n')).toContain('no active relay session')
  })

  it('reports an active session on status', async () => {
    await writeSessionLock(SERVER, {
      sessionId: 'abcd1234ef',
      relayUrl: 'https://relay.example/s/abcd1234',
      createdAt: Date.now()
    })
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['relay', 'status'])).toBe(0)
    expect(logs[0]).toContain('session abcd1234')
    expect(logs[0]).toContain('relay_url=https://relay.example/s/abcd1234')
  })

  it('clears relay state on reset', async () => {
    await writeSessionLock(SERVER, {
      sessionId: 'abcd1234ef',
      relayUrl: 'https://relay.example/s/abcd1234',
      createdAt: Date.now()
    })
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['relay', 'reset'])).toBe(0)
    expect(logs[0]).toBe(`${SERVER}: relay state cleared`)
    // Status now reports no session.
    expect(await run(['relay', 'status'])).toBe(1)
  })

  it('opens the active session URL', async () => {
    await writeSessionLock(SERVER, {
      sessionId: 'abcd1234ef',
      relayUrl: 'https://relay.example/s/abcd1234',
      createdAt: Date.now()
    })
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['relay', 'open'])).toBe(0)
    expect(logs[0]).toBe(`${SERVER}: opened https://relay.example/s/abcd1234`)
  })

  it('reports no session to open with rc 1', async () => {
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['relay', 'open'])).toBe(1)
    expect(errs.join('\n')).toContain('no active relay session')
  })

  it('returns rc 2 on an invalid relay action', async () => {
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['relay', 'bogus'])).toBe(2)
  })
})

describe('buildCli — doctor subcommand', () => {
  it('runs every check and exits per the aggregate health', async () => {
    const run = buildCli(SERVER, { serve: () => 0 })
    const rc = await run(['doctor'])
    const all = logs.join('\n')
    expect(all).toMatch(/\[(ok|fail)] node /)
    expect(all).toContain('[ok] credential backend initializes')
    expect(all).toContain('[warn] config: not configured')
    expect(all).toContain('[warn] no active relay session')
    expect(all).toContain('[ok] mode: unset')
    // doctor returns 0 iff no check failed. The runtime-version line is the only
    // check that varies by test runner: `bun run test` runs under Bun, whose
    // process.versions.node is a compat shim that some Bun builds report below
    // the >=24 floor. Assert the aggregate contract, not a fixed exit code.
    expect(rc).toBe(all.includes('[fail]') ? 1 : 0)
  })

  it('returns 1 and reports a corrupt config regardless of runtime', async () => {
    await new LocalFsBackend().put(`${SERVER}/config`, Buffer.from('too-short'))
    const run = buildCli(SERVER, { serve: () => 0 })
    expect(await run(['doctor'])).toBe(1)
    expect(logs.join('\n')).toContain('[fail] config: corrupt')
  })
})

describe('buildCli — extra subcommands', () => {
  it('lets an extra subcommand override a built-in', async () => {
    const run = buildCli(SERVER, { serve: () => 0, extra: { doctor: () => 42 } })
    expect(await run(['doctor'])).toBe(42)
  })

  it('passes the remaining argv to an extra handler', async () => {
    const run = buildCli(SERVER, {
      serve: () => 0,
      extra: { auth: (rest) => (rest[0] === 'google' ? 0 : 2) }
    })
    expect(await run(['auth', 'google'])).toBe(0)
    expect(await run(['auth', 'github'])).toBe(2)
  })
})
