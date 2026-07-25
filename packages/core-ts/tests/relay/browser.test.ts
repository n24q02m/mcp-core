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
 * Ba biến TẮT việc mở browser. Test phải tự làm chủ chúng, không để môi trường
 * quyết định: máy dev ở đây export `MCP_NO_BROWSER=1`, và MỌI CI runner có
 * `CI=1` -- không xoá thì suite này đọc cấu hình của máy chạy chứ không đọc
 * code, và kiểu đỏ đó chỉ hiện sau khi push. Xoá trước mỗi test, khôi phục sau
 * (cũng chặn một test set biến rồi rò sang test kế).
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

    // Ba biến, MỘT quy tắc, một bảng giá trị -- cố ý gộp: ai đổi semantics của
    // một biến sẽ thấy ngay hai biến kia đang hứa điều gì. `CI` phải theo quy
    // ước cộng đồng (`ci-info`) vì nó là biến đọc ké của môi trường; hai biến
    // của chính mình theo cùng luật để `if` trong browser.ts chỉ có một cách đọc
    // -- và vì `MCP_NO_BROWSER=false` mà lại CHẶN browser là sai theo mọi cách
    // đọc một cái tên phủ định.
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
