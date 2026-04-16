/**
 * Cross-platform browser opening with WSL detection.
 */

import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

// Dedupe repeated tryOpenBrowser calls for the same URL. OAuth verification
// URLs are stable so a retry loop would otherwise spawn a new tab per attempt.
// Keep a 5-minute window per URL.
const BROWSER_OPEN_DEDUPE_WINDOW_MS = 5 * 60 * 1000
const recentBrowserOpens = new Map<string, number>()

async function isWsl(): Promise<boolean> {
  try {
    const version = await readFile('/proc/version', 'utf-8')
    const lower = version.toLowerCase()
    return lower.includes('microsoft') || lower.includes('wsl')
  } catch {
    return false
  }
}

async function openInWsl(url: string): Promise<boolean> {
  // Try wslview first (from wslu package, commonly available)
  try {
    await execFileAsync('wslview', [url])
    return true
  } catch {
    /* fall through */
  }

  // Fallback to rundll32.exe url.dll,FileProtocolHandler
  try {
    await execFileAsync('rundll32.exe', ['url.dll,FileProtocolHandler', url])
    return true
  } catch {
    /* fall through */
  }

  return false
}

/**
 * Try to open URL in default browser. Returns true if likely succeeded.
 *
 * Detection order:
 * 1. win32: rundll32.exe
 * 2. darwin: `open` command
 * 3. linux: check WSL then `xdg-open`
 *
 * Never throws. Returns false on failure.
 */
export async function tryOpenBrowser(url: string): Promise<boolean> {
  try {
    // Validate URL
    try {
      const parsedUrl = new URL(url)
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        return false
      }
    } catch {
      return false
    }

    // Reject shell metacharacters and spaces to prevent command injection.
    // Ampersands are allowed for legitimate query parameters.
    // biome-ignore lint/suspicious/noControlCharactersInRegex: Control characters are explicitly disallowed for security.
    if (/[\s;|><\\`$()\x00-\x1F\x7F]/.test(url)) {
      return false
    }

    const lastOpened = recentBrowserOpens.get(url)
    if (lastOpened !== undefined && Date.now() - lastOpened < BROWSER_OPEN_DEDUPE_WINDOW_MS) {
      return true
    }
    recentBrowserOpens.set(url, Date.now())

    const platform = process.platform

    if (platform === 'win32') {
      await execFileAsync('rundll32.exe', ['url.dll,FileProtocolHandler', url])
      return true
    }

    if (platform === 'darwin') {
      await execFileAsync('open', [url])
      return true
    }

    // linux
    if (await isWsl()) {
      const result = await openInWsl(url)
      if (result) return true
      // Fall through to xdg-open
    }

    await execFileAsync('xdg-open', [url])
    return true
  } catch {
    return false
  }
}
