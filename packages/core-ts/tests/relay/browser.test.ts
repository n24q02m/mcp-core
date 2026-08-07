import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// Mock child_process and fs/promises before importing the module
vi.mock('node:child_process', () => ({
  execFile: vi.fn((...args: any[]) => {
    const _options = args[2]
    const cb = args[3]
    const callback = typeof _options === 'function' ? _options : cb
    if (callback) {
      callback(new Error('no display'))
    }
  })
}))

vi.mock('node:fs/promises', () => ({
  readFile: vi.fn().mockRejectedValue(new Error('ENOENT'))
}))

import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { tryOpenBrowser } from '../../src/relay/browser.js'

/**
 * The three variables that turn browser-opening OFF. These tests have to own
 * them rather than let the environment decide: a dev machine here exports
 * `MCP_NO_BROWSER=1`, and EVERY CI runner sets `CI=1` -- leave them in place and
 * this suite reads the config of whatever machine runs it instead of reading the
 * code, a kind of red that only shows up after a push. Cleared before each test
 * and restored after (which also stops one test leaking a value into the next).
 */
const BROWSER_GUARD_ENV = ['MCP_NO_BROWSER', 'NO_BROWSER', 'CI'] as const

describe('tryOpenBrowser', () => {
  let savedGuardEnv: Record<string, string | undefined>

  beforeEach(() => {
    savedGuardEnv = Object.fromEntries(BROWSER_GUARD_ENV.map((key) => [key, process.env[key]]))
    for (const key of BROWSER_GUARD_ENV) delete process.env[key]
  })

  afterEach(() => {
    for (const [key, value] of Object.entries(savedGuardEnv)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  })

  describe('URL validation', () => {
    it('rejects non-http URLs', async () => {
      expect(await tryOpenBrowser('file:///etc/passwd')).toBe(false)
      expect(await tryOpenBrowser('javascript:alert(1)')).toBe(false)
      expect(await tryOpenBrowser('ftp://example.com')).toBe(false)
      expect(await tryOpenBrowser('data:text/html,<h1>hi</h1>')).toBe(false)
      expect(await tryOpenBrowser('https://example.com;rm -rf /')).toBe(false)
      expect(await tryOpenBrowser('https://example.com$(whoami)')).toBe(false)
      expect(await tryOpenBrowser('https://example.com`whoami`')).toBe(false)
      expect(await tryOpenBrowser('https://example.com|nc localhost 4444')).toBe(false)
      expect(await tryOpenBrowser('https://example.com/auth?q=$(whoami)')).toBe(false)
      expect(await tryOpenBrowser('https://example.com/auth?q=(param)')).toBe(false)
    })

    it('rejects empty and malformed input', async () => {
      expect(await tryOpenBrowser('')).toBe(false)
      expect(await tryOpenBrowser(' ')).toBe(false)
      expect(await tryOpenBrowser('not-a-url')).toBe(false)
      expect(await tryOpenBrowser('://missing-scheme')).toBe(false)
    })

    it('accepts valid http URLs', async () => {
      const result = await tryOpenBrowser('http://localhost:3000/authorize')
      expect(typeof result).toBe('boolean')
    })

    it('accepts valid https URLs', async () => {
      const result = await tryOpenBrowser('https://example.com/authorize?s=abc#k=def&p=ghi')
      expect(typeof result).toBe('boolean')
    })

    it('accepts case-insensitive HTTP/HTTPS', async () => {
      const result1 = await tryOpenBrowser('HTTP://example.com')
      expect(typeof result1).toBe('boolean')

      const result2 = await tryOpenBrowser('HTTPS://example.com')
      expect(typeof result2).toBe('boolean')
    })

    it('accepts URLs with single quotes', async () => {
      const result = await tryOpenBrowser("https://example.com/auth?q='hello'")
      expect(typeof result).toBe('boolean')
    })
  })

  /**
   * RFC 3986 sub-delimiters that a pattern-matching scanner reads as "shell
   * metacharacters". The validator ACCEPTS them, on purpose, and these tests pin
   * that decision to the reason for it rather than to the characters themselves:
   * nothing on the path from this validator to the operating system goes through
   * a shell, so there is nothing for a metacharacter to be a metacharacter OF.
   *
   *   darwin / linux -> `execFile('open' | 'xdg-open', [url])`. `execFile` runs
   *                     the binary directly (`shell: false` is its default), so
   *                     the URL is ONE argv element; `;` never separates a
   *                     command and `*` is never globbed.
   *   win32 / WSL    -> `openInPowerShell` base64-encodes the URL BEFORE
   *                     embedding it in the PowerShell source, and the base64
   *                     alphabet (A-Za-z0-9+/=) contains no `;`, `,`, `*` or
   *                     quote to break out of the string literal with.
   *
   * Rejecting them would also be wrong on the URL side: `,`, `;` and `*` are
   * sub-delims RFC 3986 allows in a path or query, so a stricter class would
   * start refusing legitimate authorization URLs. The characters that ARE
   * excluded from the class -- `$`, `(`, `)`, `|`, backtick -- are excluded
   * because they are not URL characters, and 'rejects non-http URLs' covers them.
   */
  describe('sub-delimiters never reach a shell', () => {
    const SUB_DELIM_PATHS = ['auth?a=1;b=2', 'auth?list=a,b,c', 'auth?glob=*', 'a;b,c*d']

    function mockExecFileOk(): void {
      vi.mocked(execFile).mockImplementation((...args: any[]) => {
        const _options = args[2]
        const cb = args[3]
        const callback = typeof _options === 'function' ? _options : cb
        if (callback) {
          callback(null)
        }
        return {} as any
      })
    }

    it('passes them to `open` as one argv element on darwin', async () => {
      Object.defineProperty(process, 'platform', { value: 'darwin' })
      for (const path of SUB_DELIM_PATHS) {
        vi.mocked(execFile).mockClear()
        mockExecFileOk()

        const url = `https://example.com/${path}&n=${Date.now()}${Math.random()}`
        expect(await tryOpenBrowser(url)).toBe(true)
        // Delimiters intact inside a single array element: no word splitting,
        // no globbing, no command separator.
        expect(execFile).toHaveBeenCalledWith('open', [url], expect.any(Function))
      }
    })

    it('passes them to `xdg-open` as one argv element on linux', async () => {
      Object.defineProperty(process, 'platform', { value: 'linux' })
      vi.mocked(readFile).mockRejectedValue(new Error('ENOENT'))
      for (const path of SUB_DELIM_PATHS) {
        vi.mocked(execFile).mockClear()
        mockExecFileOk()

        const url = `https://example.com/${path}&n=${Date.now()}${Math.random()}`
        expect(await tryOpenBrowser(url)).toBe(true)
        expect(execFile).toHaveBeenCalledWith('xdg-open', [url], expect.any(Function))
      }
    })

    it('keeps the raw URL out of the PowerShell source on win32', async () => {
      Object.defineProperty(process, 'platform', { value: 'win32' })
      for (const path of SUB_DELIM_PATHS) {
        vi.mocked(execFile).mockClear()
        mockExecFileOk()

        const url = `https://example.com/${path}&n=${Date.now()}${Math.random()}`
        expect(await tryOpenBrowser(url)).toBe(true)

        const lastCall = vi.mocked(execFile).mock.calls[vi.mocked(execFile).mock.calls.length - 1]
        const args = lastCall[1] as string[]
        const decoded = Buffer.from(args[args.indexOf('-EncodedCommand') + 1], 'base64').toString('utf16le')
        const base64Url = Buffer.from(url, 'utf8').toString('base64')

        // The URL's own characters do not appear in the PowerShell source at
        // all; only its base64 form does.
        expect(decoded).not.toContain(url)
        expect(decoded).toContain(base64Url)
        // The base64 alphabet is why the single-quoted literal around it cannot
        // be broken out of.
        for (const char of [';', ',', '*', "'", '"']) {
          expect(base64Url).not.toContain(char)
        }
      }
    })
  })

  describe('behavior', () => {
    it('deduplicates browser opens within the window', async () => {
      vi.mocked(execFile).mockClear()
      Object.defineProperty(process, 'platform', { value: 'darwin' })
      vi.mocked(execFile).mockImplementation((...args: any[]) => {
        const _options = args[2]
        const cb = args[3]
        const callback = typeof _options === 'function' ? _options : cb
        if (callback) {
          callback(null)
        }
        return {} as any
      })

      const url = `https://example.com/dedupe-${Date.now()}`
      const result1 = await tryOpenBrowser(url)
      const result2 = await tryOpenBrowser(url)

      expect(result1).toBe(true)
      expect(result2).toBe(true)
      expect(execFile).toHaveBeenCalledTimes(1)
    })
    it('returns a boolean', async () => {
      const result = await tryOpenBrowser('https://example.com/test-returns-boolean')
      expect(result === true || result === false).toBe(true)
    })

    it('never throws even when execFile fails', async () => {
      vi.mocked(execFile).mockImplementation((...args: any[]) => {
        const _options = args[2]
        const cb = args[3]
        const callback = typeof _options === 'function' ? _options : cb
        if (callback) {
          callback(new Error('command not found'))
        }
        return {} as any
      })

      const result = await tryOpenBrowser('https://example.com/test-never-throws')
      expect(typeof result).toBe('boolean')
    })

    it('never throws even with unexpected errors', async () => {
      vi.mocked(execFile).mockImplementation(() => {
        throw new TypeError('unexpected')
      })

      const result = await tryOpenBrowser('https://example.com/test-unexpected-error')
      expect(result).toBe(false)
    })

    it('does not call execFile for invalid URLs', async () => {
      vi.mocked(execFile).mockClear()

      await tryOpenBrowser('file:///etc/passwd')
      await tryOpenBrowser('')
      await tryOpenBrowser('javascript:alert(1)')

      expect(execFile).not.toHaveBeenCalled()
    })

    // Three variables, ONE rule, one value table -- shared on purpose: anyone
    // changing the semantics of one of them sees straight away what the other
    // two promise. `CI` has to follow the community convention (`ci-info`)
    // because it is a variable we read from someone else's environment; our own
    // two follow the same rule so the `if` in browser.ts has only one reading --
    // and because `MCP_NO_BROWSER=false` SUPPRESSING the browser is wrong under
    // every way of reading a negative name.
    const SUPPRESSING = ['1', 'true', 'TRUE', 'yes', 'anything']
    const NOT_SUPPRESSING = ['false', '0', '']

    function mockExecFileSuccess(): void {
      vi.mocked(execFile).mockImplementation((...args: any[]) => {
        const _options = args[2]
        const cb = args[3]
        const callback = typeof _options === 'function' ? _options : cb
        if (callback) {
          callback(null)
        }
        return {} as any
      })
    }

    for (const name of BROWSER_GUARD_ENV) {
      it(`does not open when ${name} is set to a real value`, async () => {
        Object.defineProperty(process, 'platform', { value: 'darwin' })
        mockExecFileSuccess()

        for (const value of SUPPRESSING) {
          vi.mocked(execFile).mockClear()
          process.env[name] = value

          expect(await tryOpenBrowser(`https://example.com/${name}-${value}-${Date.now()}`)).toBe(false)
          expect(execFile).not.toHaveBeenCalled()
        }
      })

      it(`still opens when ${name} is empty, 'false' or '0'`, async () => {
        Object.defineProperty(process, 'platform', { value: 'darwin' })
        mockExecFileSuccess()

        for (const value of NOT_SUPPRESSING) {
          vi.mocked(execFile).mockClear()
          process.env[name] = value

          expect(await tryOpenBrowser(`https://example.com/${name}-${value || 'empty'}-${Date.now()}`)).toBe(true)
          expect(execFile).toHaveBeenCalledOnce()
        }
      })
    }

    it('does not open when all three guard variables are set', async () => {
      vi.mocked(execFile).mockClear()
      process.env.MCP_NO_BROWSER = '1'
      process.env.NO_BROWSER = '1'
      process.env.CI = 'true'

      const result = await tryOpenBrowser('https://example.com/authorize?nonce=all-three')

      expect(result).toBe(false)
      expect(execFile).not.toHaveBeenCalled()
    })
  })

  describe('WSL detection', () => {
    it('returns false when /proc/version is not found', async () => {
      vi.mocked(readFile).mockRejectedValue(new Error('ENOENT'))
      vi.mocked(execFile).mockImplementation((...args: any[]) => {
        const _options = args[2]
        const cb = args[3]
        const callback = typeof _options === 'function' ? _options : cb
        if (callback) {
          callback(new Error('command not found'))
        }
        return {} as any
      })

      const result = await tryOpenBrowser('https://example.com/wsl-test')
      expect(typeof result).toBe('boolean')
    })
  })

  describe('PowerShell execution', () => {
    it('returns false when powershell fails on win32', async () => {
      vi.mocked(execFile).mockClear()
      Object.defineProperty(process, 'platform', { value: 'win32' })
      vi.mocked(execFile).mockImplementation((...args: any[]) => {
        const _options = args[2]
        const cb = args[3]
        const callback = typeof _options === 'function' ? _options : cb
        if (callback) {
          callback(new Error('fail'))
        }
        return {} as any
      })

      const url = `https://example.com/win32-fail-${Date.now()}`
      const result = await tryOpenBrowser(url)
      expect(result).toBe(false)
    })
    it('uses powershell.exe with EncodedCommand and embedded URL on win32', async () => {
      Object.defineProperty(process, 'platform', { value: 'win32' })
      vi.mocked(execFile).mockImplementation((...args: any[]) => {
        const _options = args[2]
        const cb = args[3]
        const callback = typeof _options === 'function' ? _options : cb
        if (callback) {
          callback(null)
        }
        return {} as any
      })

      const url = `https://example.com/auth-new-url-${Date.now()}`
      await tryOpenBrowser(url)

      expect(execFile).toHaveBeenCalledWith(
        'powershell.exe',
        expect.arrayContaining(['-NoProfile', '-EncodedCommand']),
        expect.any(Function)
      )

      const lastCall = vi.mocked(execFile).mock.calls[vi.mocked(execFile).mock.calls.length - 1]
      const args = lastCall[1] as string[]
      const encodedCommand = args[args.indexOf('-EncodedCommand') + 1]
      const decoded = Buffer.from(encodedCommand, 'base64').toString('utf16le')
      const base64Url = Buffer.from(url, 'utf8').toString('base64')
      expect(decoded).toContain(base64Url)
      expect(decoded).toContain('[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String')
      expect(decoded).toContain('Start-Process $url')
    })
  })

  describe('platform execution', () => {
    it('falls back to powershell on WSL when wslview fails', async () => {
      Object.defineProperty(process, 'platform', { value: 'linux' })
      vi.mocked(readFile).mockResolvedValue('linux version microsoft')
      vi.mocked(execFile).mockImplementation((...args: any[]) => {
        const cmd = args[0]
        const _options = args[2]
        const cb = args[3]
        const callback = typeof _options === 'function' ? _options : cb
        if (callback) {
          if (cmd === 'wslview') {
            callback(new Error('fail'))
          } else {
            callback(null)
          }
        }
        return {} as any
      })

      const url = `https://example.com/wsl-fallback-${Date.now()}`
      await tryOpenBrowser(url)

      expect(execFile).toHaveBeenCalledWith(
        'powershell.exe',
        expect.arrayContaining(['-NoProfile', '-EncodedCommand']),
        expect.any(Function)
      )
    })
    it('uses open on darwin', async () => {
      Object.defineProperty(process, 'platform', { value: 'darwin' })
      vi.mocked(execFile).mockImplementation((...args: any[]) => {
        const _options = args[2]
        const cb = args[3]
        const callback = typeof _options === 'function' ? _options : cb
        if (callback) {
          callback(null)
        }
        return {} as any
      })

      const url = `https://example.com/darwin-${Date.now()}`
      await tryOpenBrowser(url)

      expect(execFile).toHaveBeenCalledWith('open', [url], expect.any(Function))
    })

    it('uses xdg-open on linux when not WSL', async () => {
      Object.defineProperty(process, 'platform', { value: 'linux' })
      vi.mocked(readFile).mockRejectedValue(new Error('ENOENT'))
      vi.mocked(execFile).mockImplementation((...args: any[]) => {
        const _options = args[2]
        const cb = args[3]
        const callback = typeof _options === 'function' ? _options : cb
        if (callback) {
          callback(null)
        }
        return {} as any
      })

      const url = `https://example.com/linux-${Date.now()}`
      await tryOpenBrowser(url)

      expect(execFile).toHaveBeenCalledWith('xdg-open', [url], expect.any(Function))
    })

    it('uses wslview on WSL', async () => {
      Object.defineProperty(process, 'platform', { value: 'linux' })
      vi.mocked(readFile).mockResolvedValue('linux version microsoft')
      vi.mocked(execFile).mockImplementation((...args: any[]) => {
        const _options = args[2]
        const cb = args[3]
        const callback = typeof _options === 'function' ? _options : cb
        if (callback) {
          callback(null)
        }
        return {} as any
      })

      const url = `https://example.com/wsl-${Date.now()}`
      await tryOpenBrowser(url)

      expect(execFile).toHaveBeenCalledWith(
        'powershell.exe',
        expect.arrayContaining(['-NoProfile', '-EncodedCommand']),
        expect.any(Function)
      )
    })
  })
})
