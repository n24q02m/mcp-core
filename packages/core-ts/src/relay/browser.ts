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

  // Fallback to powershell EncodedCommand
  try {
    const escapedUrl = url.replace(/'/g, "''")
    const psCommand = `Start-Process '${escapedUrl}'`
    const encoded = Buffer.from(psCommand, 'utf16le').toString('base64')
    await execFileAsync('powershell.exe', ['-NoProfile', '-EncodedCommand', encoded])
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
    if (!/^https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+$/.test(url)) {
      return false
    }

    const lastOpened = recentBrowserOpens.get(url)
    if (lastOpened !== undefined && Date.now() - lastOpened < BROWSER_OPEN_DEDUPE_WINDOW_MS) {
      return true
    }
    recentBrowserOpens.set(url, Date.now())

    const platform = process.platform

    if (platform === 'win32') {
      const escapedUrl = url.replace(/'/g, "''")
      const psCommand = `Start-Process '${escapedUrl}'`
      const encoded = Buffer.from(psCommand, 'utf16le').toString('base64')
      await execFileAsync('powershell.exe', ['-NoProfile', '-EncodedCommand', encoded])
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
