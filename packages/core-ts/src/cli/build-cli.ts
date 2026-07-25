/**
 * Console-script CLI builder shared by every TypeScript MCP server.
 *
 * TS counterpart of `mcp_core.build_cli` (core-py). `buildCli` wraps a
 * server's existing `serve(argv) -> number | void` entry point with
 * subcommand dispatch, without changing that entry point's behaviour for the
 * two invocation shapes it already handles:
 *
 * - Bare invocation (`argv` empty) still means "start the server".
 * - Any flag-prefixed argv (`--http` etc.) is passed through to `serve`
 *   byte-for-byte, so existing `--http` semantics are untouched -- except
 *   `-h`/`--help` (always) and `--version`/`-V` (only when `version` is set),
 *   which are intercepted here and never reach `serve`. Starting the server on
 *   those would hang in stdio mode instead of printing the requested output.
 *
 * A leading *positional* argv[0] is treated as a subcommand name -- either one
 * of the reserved built-ins (`config`/`relay`/`doctor`) or a server-specific
 * one supplied via `extra` -- and is routed to its handler instead of `serve`.
 * STDOUT is the MCP protocol channel in stdio mode, so only this subcommand
 * path prints to stdout; the `serve` path never touches stdout here.
 *
 * Built-in output convention: informational results (configured/not
 * configured, session details, doctor's `[ok]`/`[warn]`/`[fail]` lines) go to
 * stdout (`console.log`); failures and prompts (no active session, refused
 * delete, corrupt config) go to stderr (`console.error`) alongside a non-zero
 * return code. Credential *values* are never printed by any built-in -- only
 * names/keys/status.
 */

import { accessSync, constants, existsSync } from 'node:fs'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { tryOpenBrowser } from '../relay/browser.js'
import { backendFromEnv } from '../storage/backends.js'
import { pluginNameForServer } from '../storage/credential-store.js'
import { getHomeDir } from '../storage/home-dir.js'
import { clearMode, getMode } from '../storage/mode.js'
import { PerPluginStore } from '../storage/per-plugin-store.js'
import { acquireSessionLock, releaseSessionLock, type SessionInfo } from '../storage/session-lock.js'

// Minimum Node major the stack supports (mcp-core package.json `engines`
// pins `>=24.18.0`). Doctor's runtime check is the TS analogue of core-py's
// exact `python == 3.13` line; TS uses a floor because the package supports
// Node 24+ (its @types/node targets 26).
const MIN_NODE_MAJOR = 24

/** A server's start entry point. Returns an exit code, or nothing for 0. */
export type ServeFn = (argv: string[]) => number | void | Promise<number | void>

/**
 * A subcommand handler. Receives the argv that follows the subcommand name
 * (e.g. for `config status --yes` the handler gets `['status', '--yes']`) and
 * returns the process exit code.
 */
export type CliHandler = (argv: string[]) => number | Promise<number>

export interface BuildCliOptions {
  /** The server's start entry point (bare/flag argv routes here). */
  serve: ServeFn
  /**
   * Server-specific subcommands. A name here overrides the reserved built-in
   * of the same name (`config`/`relay`/`doctor`), so a server can supply its
   * own handler.
   */
  extra?: Record<string, CliHandler>
  /** Powers `--version`/`-V`. When unset, those flags fall through to serve. */
  version?: string
  /**
   * Credential storage plugin slug (e.g. `"wet"`): decides where `config` and
   * `doctor` read/write via `PerPluginStore`. Servers save credentials under
   * this slug, not the console name, so the two must not be conflated. When
   * omitted it defaults to `serverName` with a trailing `"-mcp"` stripped,
   * which matches the wet/mnemo/crg convention; pass it explicitly when the
   * slug differs (telegram saves under `"telegram"` though its console name
   * is `"better-telegram-mcp"`).
   */
  pluginName?: string
}

function printCliHelp(serverName: string, handlers: Record<string, CliHandler>): void {
  const names = Object.keys(handlers).sort().join(', ')
  console.log(`usage: ${serverName} [-h] [--version] [<subcommand> ...]`)
  console.log('Any other flags/args are passed through to the MCP server (e.g. --http).')
  console.log(`subcommands: ${names}`)
}

async function configStatus(serverName: string, pluginName: string): Promise<number> {
  // Credentials are keyed by the plugin slug (what the server saves under),
  // while `serverName` stays the display label in the printed status.
  const store = new PerPluginStore(pluginName)
  if ((await store.load()) !== null) {
    console.log(`${serverName}: configured (source: file)`)
    console.log('  (env overrides, if any, take precedence at server start)')
    return 0
  }
  // load() returns null for both "absent" and "corrupt"; the raw backend read
  // tells them apart without ever touching the plaintext.
  if (await store.hasStoredBlob()) {
    console.error(`${serverName}: config is corrupt (undecryptable) -- re-run setup to restore`)
    return 1
  }
  console.log(`${serverName}: not configured`)
  console.log('  (env overrides, if any, take precedence at server start)')
  return 0
}

async function confirmDelete(serverName: string): Promise<boolean> {
  process.stderr.write(`Delete stored config for ${serverName}? [y/N] `)
  const rl = createInterface({ input: process.stdin })
  try {
    const line = await new Promise<string>((resolve) => {
      rl.once('line', resolve)
    })
    return ['y', 'yes'].includes(line.trim().toLowerCase())
  } finally {
    rl.close()
  }
}

async function configDelete(serverName: string, pluginName: string, yes: boolean): Promise<number> {
  if (!yes) {
    if (!process.stdin.isTTY) {
      console.error(`${serverName}: refusing to delete without --yes in non-interactive mode`)
      return 1
    }
    if (!(await confirmDelete(serverName))) {
      console.error(`${serverName}: aborted`)
      return 1
    }
  }
  await new PerPluginStore(pluginName).clear()
  console.log(`${serverName}: config deleted`)
  return 0
}

function configHandler(serverName: string, pluginName: string): CliHandler {
  return async (argv) => {
    const action = argv[0]
    if (action === 'status') return configStatus(serverName, pluginName)
    if (action === 'delete') return configDelete(serverName, pluginName, argv.includes('--yes'))
    console.error(`${serverName}: config expects 'status' or 'delete'`)
    return 2
  }
}

function relayStatus(serverName: string, info: SessionInfo | null): number {
  if (info === null) {
    console.error(`${serverName}: no active relay session`)
    return 1
  }
  const ageS = (Date.now() - info.createdAt) / 1000
  console.log(`${serverName}: session ${info.sessionId.slice(0, 8)} relay_url=${info.relayUrl} age=${ageS.toFixed(0)}s`)
  return 0
}

function relayHandler(serverName: string): CliHandler {
  return async (argv) => {
    const action = argv[0]
    if (action === 'reset') {
      await releaseSessionLock(serverName)
      await clearMode(serverName)
      console.log(`${serverName}: relay state cleared`)
      return 0
    }
    if (action !== 'status' && action !== 'open') {
      console.error(`${serverName}: relay expects 'status', 'open', or 'reset'`)
      return 2
    }
    const info = await acquireSessionLock(serverName)
    if (action === 'status') return relayStatus(serverName, info)
    // "open"
    if (info === null) {
      console.error(`${serverName}: no active relay session`)
      return 1
    }
    // Branch on the return value: `tryOpenBrowser` declines under headless / CI
    // / the env-guard, and printing "opened" there is untrue in the very first
    // line the user reads -- they wait for a tab that never appears. Failing to
    // open is not a failure of the command (the URL is still correct and still
    // usable), so the exit code stays 0.
    if (await tryOpenBrowser(info.relayUrl)) {
      console.log(`${serverName}: opened ${info.relayUrl}`)
    } else {
      console.log(`${serverName}: could not launch a browser here; visit ${info.relayUrl}`)
    }
    return 0
  }
}

async function runDoctor(serverName: string, pluginName: string): Promise<number> {
  let ok = true

  const nodeVersion = process.versions.node
  if (Number(nodeVersion.split('.')[0]) >= MIN_NODE_MAJOR) {
    console.log(`[ok] node ${nodeVersion}`)
  } else {
    console.log(`[fail] node ${nodeVersion} (expected >=${MIN_NODE_MAJOR})`)
    ok = false
  }

  try {
    backendFromEnv()
    console.log('[ok] credential backend initializes')
  } catch (err) {
    console.log(`[fail] credential backend: ${(err as Error).message}`)
    ok = false
  }

  // Only check writability if the dir already exists -- doctor must not create
  // it as a side effect (mkdir-probing would leave stray dirs for servers that
  // were never configured). The dir is keyed by the plugin slug (matching
  // PerPluginStore's on-disk layout), not the console name.
  const storeDir = join(getHomeDir(), `.${pluginName}-mcp`)
  if (existsSync(storeDir)) {
    try {
      accessSync(storeDir, constants.W_OK)
      console.log(`[ok] store dir writable: ${storeDir}`)
    } catch {
      console.log(`[fail] store dir not writable: ${storeDir}`)
      ok = false
    }
  } else {
    console.log(`[warn] store dir does not exist yet: ${storeDir}`)
  }

  const store = new PerPluginStore(pluginName)
  if ((await store.load()) !== null) {
    console.log('[ok] config: configured')
  } else if (await store.hasStoredBlob()) {
    console.log('[fail] config: corrupt')
    ok = false
  } else {
    console.log('[warn] config: not configured')
  }

  const info = await acquireSessionLock(serverName)
  if (info !== null) {
    console.log(`[ok] relay session active (${info.sessionId.slice(0, 8)})`)
  } else {
    console.log('[warn] no active relay session')
  }

  console.log(`[ok] mode: ${(await getMode(serverName)) ?? 'unset'}`)

  return ok ? 0 : 1
}

function doctorHandler(serverName: string, pluginName: string): CliHandler {
  return () => runDoctor(serverName, pluginName)
}

/**
 * Build the console-script entry point for one MCP server.
 *
 * `serverName` is the console/display name (e.g. `"wet-mcp"`): it names the
 * program in help/usage and status lines, and keys relay session state and
 * run mode (which servers store under their `SERVER_NAME`).
 *
 * `options.pluginName` is the credential storage slug that `PerPluginStore`
 * keys on (e.g. `"wet"`): it decides where `config` and `doctor` read/write
 * credentials. Servers save creds under this slug, not under the console
 * name, so the two must not be conflated. When omitted it defaults to
 * `serverName` with a trailing `"-mcp"` stripped, which matches the wet/
 * mnemo/crg convention; pass it explicitly when the slug differs (telegram
 * saves under `"telegram"` though its console name is `"better-telegram-mcp"`).
 *
 * `extra` subcommand names take precedence over the reserved built-ins, so a
 * server (or a test) can supply its own `doctor`/`config`/`relay` handler.
 * `version`, when set, powers `--version`/`-V` (handled before `serve` or any
 * subcommand runs); when unset, `--version`/`-V` falls through to `serve` like
 * any other flag.
 *
 * The returned `run(argv)` resolves to the process exit code. A server's entry
 * point calls it and exits: `buildCli(name, opts)(process.argv.slice(2)).then((c) => process.exit(c))`.
 */
export function buildCli(serverName: string, options: BuildCliOptions): (argv?: string[] | null) => Promise<number> {
  const { serve, extra, version, pluginName = pluginNameForServer(serverName) } = options
  const handlers: Record<string, CliHandler> = {
    config: configHandler(serverName, pluginName),
    relay: relayHandler(serverName),
    doctor: doctorHandler(serverName, pluginName),
    ...extra
  }

  return async (argv?: string[] | null): Promise<number> => {
    const args = argv ?? process.argv.slice(2)

    if (args.length === 0) {
      const rc = await serve([])
      return rc == null ? 0 : rc
    }

    // Peek argv[0] before any subcommand routing: bare/flag argv must never
    // reach a subcommand handler, or `--http` would be misread instead of
    // passed through to `serve`. `-h`/`--help`/`--version` are intercepted
    // here because starting the server on them would hang (stdio blocks on
    // stdin) instead of printing the requested output.
    if (args[0] === '-h' || args[0] === '--help') {
      printCliHelp(serverName, handlers)
      return 0
    }

    if (version != null && (args[0] === '--version' || args[0] === '-V')) {
      console.log(`${serverName} ${version}`)
      return 0
    }

    if (args[0].startsWith('-')) {
      const rc = await serve(args)
      return rc == null ? 0 : rc
    }

    const subcommand = args[0]
    const handler = handlers[subcommand]
    if (handler === undefined) {
      const names = Object.keys(handlers).sort().join(', ')
      console.error(`${serverName}: unknown subcommand '${subcommand}' (expected one of: ${names})`)
      return 2
    }
    return handler(args.slice(1))
  }
}
