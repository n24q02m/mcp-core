import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// Mock thay vì dựa vào env-guard: `relay open` giờ RẼ NHÁNH theo giá trị trả về
// của tryOpenBrowser, nên test phải lái được cả hai nhánh. Mock cũng là lớp an
// toàn thật sự để không có browser nào bị mở trong test -- chắc hơn một biến môi
// trường mà người chạy test có thể vô tình xoá.
const { tryOpenBrowserMock } = vi.hoisted(() => ({ tryOpenBrowserMock: vi.fn(async () => true) }))
vi.mock('../relay/browser.js', () => ({ tryOpenBrowser: tryOpenBrowserMock }))

import {
  LocalFsBackend,
  PerPluginStore,
  setConfigPath,
  setHomeDirForTesting,
  setLockDir,
  writeConfig,
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
  tryOpenBrowserMock.mockReset()
  tryOpenBrowserMock.mockResolvedValue(true)
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

  it('sees a single-user credential saved through the unified writeConfig', async () => {
    // Storage-unify contract: a server that persists single-user credentials
    // via mcp-core's public `writeConfig` (keyed by console name) writes to the
    // same per-plugin store `config status` reads (keyed by the derived slug),
    // so the CLI reports "configured" -- the whole point of the unification.
    await writeConfig('better-email-mcp', { EMAIL_CREDENTIALS: 'a@b.com:app-pass' })
    const run = buildCli('better-email-mcp', { serve: () => 0 })
    expect(await run(['config', 'status'])).toBe(0)
    expect(logs[0]).toBe('better-email-mcp: configured (source: file)')
    // A credential value is never printed by a built-in.
    expect(logs.join('\n')).not.toContain('app-pass')
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

  // Trước đây lệnh in "opened" bất kể kết quả, nên trong headless / CI / khi có
  // env-guard nó nói sai ngay câu đầu và người dùng chờ một tab không bao giờ hiện.
  it('says it could not launch a browser, and still hands over the URL', async () => {
    tryOpenBrowserMock.mockResolvedValue(false)
    await writeSessionLock(SERVER, {
      sessionId: 'abcd1234ef',
      relayUrl: 'https://relay.example/s/abcd1234',
      createdAt: Date.now()
    })
    const run = buildCli(SERVER, { serve: () => 0 })

    // Không mở được browser KHÔNG phải lỗi của lệnh: URL vẫn đúng, exit code vẫn 0.
    expect(await run(['relay', 'open'])).toBe(0)
    expect(logs[0]).not.toContain('opened')
    expect(logs[0]).toContain('https://relay.example/s/abcd1234')
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

describe('buildCli — pluginName / serverName separation (store key vs display)', () => {
  it('derives pluginName from serverName by stripping a trailing -mcp suffix', async () => {
    // Credentials are saved under the plugin slug ("w51"), which is the
    // console name ("w51-mcp") with the "-mcp" suffix stripped. `config
    // status` must read that same slug, not the literal console name.
    await new PerPluginStore('w51').save({ token: 'secret' })
    const run = buildCli('w51-mcp', { serve: () => 0 })
    expect(await run(['config', 'status'])).toBe(0)
    expect(logs[0]).toBe('w51-mcp: configured (source: file)')
  })

  it('lets an explicit pluginName override the -mcp suffix default', async () => {
    // When the slug is not simply "<name>-mcp" minus "-mcp" (telegram's slug
    // is "telegram", not "better-telegram"), an explicit pluginName pins it.
    await new PerPluginStore('telegram').save({ token: 'secret' })
    const run = buildCli('better-telegram-mcp', { serve: () => 0, pluginName: 'telegram' })
    expect(await run(['config', 'status'])).toBe(0)
    expect(logs[0]).toBe('better-telegram-mcp: configured (source: file)')
  })

  it('deletes the config under the plugin slug store', async () => {
    const store = new PerPluginStore('w51')
    await store.save({ token: 'secret' })
    const run = buildCli('w51-mcp', { serve: () => 0 })
    expect(await run(['config', 'delete', '--yes'])).toBe(0)
    expect(await store.load()).toBeNull()
  })

  it('doctor reads config status under the plugin slug', async () => {
    // Assert on the config-status line only, not the aggregate rc: the
    // runtime-version check is the only line that varies by test runner (see
    // the "runs every check" test above), and is orthogonal to plugin_name.
    await new PerPluginStore('w51').save({ token: 'secret' })
    const run = buildCli('w51-mcp', { serve: () => 0 })
    await run(['doctor'])
    expect(logs.join('\n')).toContain('[ok] config: configured')
  })

  it('doctor probes the store dir under the plugin slug, not a doubled -mcp suffix', async () => {
    // Saving creates <home>/.w51-mcp/. doctor's store-dir probe must point at
    // that path (plugin slug), not the doubled <home>/.w51-mcp-mcp/. Assert on
    // that line only, not the aggregate rc (see comment above).
    await new PerPluginStore('w51').save({ token: 'secret' })
    const run = buildCli('w51-mcp', { serve: () => 0 })
    await run(['doctor'])
    const all = logs.join('\n')
    expect(all).toContain('store dir writable')
    expect(all).not.toContain('.w51-mcp-mcp')
  })

  it('keeps relay state keyed by serverName, not the derived plugin slug', async () => {
    // A lock written under "w51-mcp" must be seen by buildCli("w51-mcp") even
    // though its store slug is "w51".
    await writeSessionLock('w51-mcp', {
      sessionId: 'abcd1234ef',
      relayUrl: 'https://relay.example/s/abcd1234',
      createdAt: Date.now()
    })
    const run = buildCli('w51-mcp', { serve: () => 0 })
    expect(await run(['relay', 'status'])).toBe(0)
    expect(logs[0]).toContain('session abcd1234')
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
