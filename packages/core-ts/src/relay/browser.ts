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

async function openInPowerShell(url: string): Promise<boolean> {
  try {
    const base64Url = Buffer.from(url, 'utf8').toString('base64')
    // Use a script block that decodes the first argument ($args[0]) to avoid injection.
    // We pass the URL as a separate argument to the PowerShell process.
    const script =
      '& { $url = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[0])); Start-Process $url }'
    await execFileAsync('powershell.exe', ['-NoProfile', '-Command', script, base64Url])
    return true
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

  // Fallback to powershell.exe -Command
  return openInPowerShell(url)
}

/**
 * Try to open URL in default browser. Returns true if likely succeeded.
 *
 * Detection order:
 * 1. win32: powershell.exe -Command
 * 2. darwin: `open` command
 * 3. linux: check WSL then `xdg-open`
 *
 * Never throws. Returns false on failure.
 */
export async function tryOpenBrowser(url: string): Promise<boolean> {
  try {
    // Validate URL
    if (!/^https?:\/\/[a-zA-Z0-9-._~:/?#[\]@!$&'()*+,;=%]+$/i.test(url)) {
      return false
    }

    const lastOpened = recentBrowserOpens.get(url)
    if (lastOpened !== undefined && Date.now() - lastOpened < BROWSER_OPEN_DEDUPE_WINDOW_MS) {
      return true
    }
    recentBrowserOpens.set(url, Date.now())

    const platform = process.platform

    if (platform === 'win32') {
      return openInPowerShell(url)
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
