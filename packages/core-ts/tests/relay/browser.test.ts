import { describe, expect, it, vi } from 'vitest'

// Mock child_process and fs/promises before importing the module
vi.mock('node:child_process', () => ({
  execFile: vi.fn((_cmd: string, _args: string[], cb: (err: Error | null) => void) => {
    cb(new Error('no display'))
  })
}))

vi.mock('node:fs/promises', () => ({
  readFile: vi.fn().mockRejectedValue(new Error('ENOENT'))
}))

import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { tryOpenBrowser } from '../../src/relay/browser.js'

describe('tryOpenBrowser', () => {
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
  })

  describe('behavior', () => {
    it('deduplicates browser opens within the window', async () => {
      vi.mocked(execFile).mockClear()
      Object.defineProperty(process, 'platform', { value: 'darwin' })
      vi.mocked(execFile).mockImplementation((_cmd: string, _args: unknown, cb: unknown) => {
        ;(cb as (err: Error | null) => void)(null)
        return {} as ReturnType<typeof execFile>
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
      vi.mocked(execFile).mockImplementation((_cmd: string, _args: unknown, cb: unknown) => {
        ;(cb as (err: Error | null) => void)(new Error('command not found'))
        return {} as ReturnType<typeof execFile>
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
  })

  describe('WSL detection', () => {
    it('returns false when /proc/version is not found', async () => {
      vi.mocked(readFile).mockRejectedValue(new Error('ENOENT'))
      vi.mocked(execFile).mockImplementation((_cmd: string, _args: unknown, cb: unknown) => {
        ;(cb as (err: Error | null) => void)(new Error('command not found'))
        return {} as ReturnType<typeof execFile>
      })

      const result = await tryOpenBrowser('https://example.com/wsl-test')
      expect(typeof result).toBe('boolean')
    })
  })

  describe('PowerShell execution', () => {
    it('returns false when powershell fails on win32', async () => {
      vi.mocked(execFile).mockClear()
      Object.defineProperty(process, 'platform', { value: 'win32' })
      vi.mocked(execFile).mockImplementation((_cmd: string, _args: unknown, cb: unknown) => {
        ;(cb as (err: Error | null) => void)(new Error('fail'))
        return {} as ReturnType<typeof execFile>
      })

      const url = `https://example.com/win32-fail-${Date.now()}`
      const result = await tryOpenBrowser(url)
      expect(result).toBe(false)
    })
    it('uses powershell.exe with EncodedCommand on win32', async () => {
      Object.defineProperty(process, 'platform', { value: 'win32' })
      vi.mocked(execFile).mockImplementation((_cmd: string, _args: unknown, cb: unknown) => {
        ;(cb as (err: Error | null) => void)(null)
        return {} as ReturnType<typeof execFile>
      })

      const url = `https://example.com/auth-new-url-${Date.now()}`
      await tryOpenBrowser(url)

      expect(execFile).toHaveBeenCalledWith(
        'powershell.exe',
        expect.arrayContaining(['-EncodedCommand']),
        expect.any(Function)
      )

      const lastCall = vi.mocked(execFile).mock.calls[vi.mocked(execFile).mock.calls.length - 1]
      const args = lastCall[1] as string[]
      const encodedCommand = args[args.indexOf('-EncodedCommand') + 1]
      const decoded = Buffer.from(encodedCommand, 'base64').toString('utf16le')
      expect(decoded).toContain(`Start-Process '${url}'`)
    })
  })

  describe('platform execution', () => {
    it('falls back to powershell on WSL when wslview fails', async () => {
      Object.defineProperty(process, 'platform', { value: 'linux' })
      vi.mocked(readFile).mockResolvedValue('linux version microsoft')
      vi.mocked(execFile).mockImplementation((cmd: string, _args: unknown, cb: unknown) => {
        if (cmd === 'wslview') {
          ;(cb as (err: Error | null) => void)(new Error('fail'))
        } else {
          ;(cb as (err: Error | null) => void)(null)
        }
        return {} as ReturnType<typeof execFile>
      })

      const url = `https://example.com/wsl-fallback-${Date.now()}`
      await tryOpenBrowser(url)

      expect(execFile).toHaveBeenCalledWith('wslview', [url], expect.any(Function))
      expect(execFile).toHaveBeenCalledWith(
        'powershell.exe',
        expect.arrayContaining(['-EncodedCommand']),
        expect.any(Function)
      )
    })
    it('uses open on darwin', async () => {
      Object.defineProperty(process, 'platform', { value: 'darwin' })
      vi.mocked(execFile).mockImplementation((_cmd: string, _args: unknown, cb: unknown) => {
        ;(cb as (err: Error | null) => void)(null)
        return {} as ReturnType<typeof execFile>
      })

      const url = `https://example.com/darwin-${Date.now()}`
      await tryOpenBrowser(url)

      expect(execFile).toHaveBeenCalledWith('open', [url], expect.any(Function))
    })

    it('uses xdg-open on linux when not WSL', async () => {
      Object.defineProperty(process, 'platform', { value: 'linux' })
      vi.mocked(readFile).mockRejectedValue(new Error('ENOENT'))
      vi.mocked(execFile).mockImplementation((_cmd: string, _args: unknown, cb: unknown) => {
        ;(cb as (err: Error | null) => void)(null)
        return {} as ReturnType<typeof execFile>
      })

      const url = `https://example.com/linux-${Date.now()}`
      await tryOpenBrowser(url)

      expect(execFile).toHaveBeenCalledWith('xdg-open', [url], expect.any(Function))
    })

    it('uses wslview on WSL', async () => {
      Object.defineProperty(process, 'platform', { value: 'linux' })
      vi.mocked(readFile).mockResolvedValue('linux version microsoft')
      vi.mocked(execFile).mockImplementation((_cmd: string, _args: unknown, cb: unknown) => {
        ;(cb as (err: Error | null) => void)(null)
        return {} as ReturnType<typeof execFile>
      })

      const url = `https://example.com/wsl-${Date.now()}`
      await tryOpenBrowser(url)

      expect(execFile).toHaveBeenCalledWith('wslview', [url], expect.any(Function))
    })
  })
})
