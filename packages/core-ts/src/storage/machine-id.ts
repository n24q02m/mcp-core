import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { hostname, networkInterfaces, userInfo } from 'node:os'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

let cachedMachineId: string | null = null

export function clearMachineIdCacheForTesting(): void {
  cachedMachineId = null
}

export async function getMachineId(): Promise<string> {
  if (cachedMachineId) return cachedMachineId

  try {
    if (process.platform === 'linux') {
      cachedMachineId = (await readFile('/etc/machine-id', 'utf-8')).trim()
      return cachedMachineId
    }
    if (process.platform === 'darwin') {
      const { stdout } = await execFileAsync('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'])
      const match = stdout.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/)
      if (match) {
        cachedMachineId = match[1]
        return cachedMachineId
      }
    }
    if (process.platform === 'win32') {
      const { stdout } = await execFileAsync('reg', [
        'query',
        'HKLM\\SOFTWARE\\Microsoft\\Cryptography',
        '/v',
        'MachineGuid'
      ])
      const match = stdout.match(/MachineGuid\s+REG_SZ\s+(\S+)/)
      if (match) {
        cachedMachineId = match[1]
        return cachedMachineId
      }
    }
  } catch {
    /* fallback below */
  }

  // Fallback: hostname + first MAC address
  const nics = networkInterfaces()
  const mac = Object.values(nics)
    .flat()
    .find((n) => n && !n.internal && n.mac !== '00:00:00:00:00:00')?.mac
  cachedMachineId = `${hostname()}-${mac ?? 'unknown'}`
  return cachedMachineId
}

export function getUsername(): string {
  try {
    return userInfo().username
  } catch {
    return process.env.USER ?? process.env.USERNAME ?? 'unknown'
  }
}
