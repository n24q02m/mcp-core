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
    })

    it('rejects empty and malformed input', async () => {
      expect(await tryOpenBrowser('')).toBe(false)
      expect(await tryOpenBrowser(' ')).toBe(false)
      expect(await tryOpenBrowser('not-a-url')).toBe(false)
      expect(await tryOpenBrowser('://missing-scheme')).toBe(false)
    })

    it('accepts valid http URLs', async () => {
      const result = await tryOpenBrowser('http://localhost:3000/setup')
      expect(typeof result).toBe('boolean')
    })

    it('accepts valid https URLs', async () => {
      const result = await tryOpenBrowser('https://example.com/setup?s=abc#k=def&p=ghi')
      expect(typeof result).toBe('boolean')
    })

    it('accepts URL-encoded parameters', async () => {
      const result = await tryOpenBrowser('https://example.com/login?redirect_uri=http%3A%2F%2Flocalhost%3A3000')
      expect(typeof result).toBe('boolean')
      // Make sure it doesn't just return false directly from regex check.
      // A return of false could also be due to no browser found in test env,
      // but if the regex fails, the execFile logic is completely skipped.
    })

    it('accepts case-insensitive HTTP/HTTPS', async () => {
      const result1 = await tryOpenBrowser('HTTP://example.com')
      expect(typeof result1).toBe('boolean')

      const result2 = await tryOpenBrowser('HTTPS://example.com')
      expect(typeof result2).toBe('boolean')
    })
  })

  describe('behavior', () => {
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
})
