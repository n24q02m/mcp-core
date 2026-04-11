import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { hostname, networkInterfaces, userInfo } from 'node:os'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

export async function getMachineId(): Promise<string> {
  try {
    if (process.platform === 'linux') {
      return (await readFile('/etc/machine-id', 'utf-8')).trim()
    }
    if (process.platform === 'darwin') {
      const { stdout } = await execFileAsync('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'])
      const match = stdout.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/)
      if (match) return match[1]
    }
    if (process.platform === 'win32') {
      const { stdout } = await execFileAsync('reg', [
        'query',
        'HKLM\\SOFTWARE\\Microsoft\\Cryptography',
        '/v',
        'MachineGuid'
      ])
      const match = stdout.match(/MachineGuid\s+REG_SZ\s+(\S+)/)
      if (match) return match[1]
    }
  } catch {
    /* fallback below */
  }

  // Fallback: hostname + first MAC address
  const nics = networkInterfaces()
  const mac = Object.values(nics)
    .flat()
    .find((n) => n && !n.internal && n.mac !== '00:00:00:00:00:00')?.mac
  return `${hostname()}-${mac ?? 'unknown'}`
}

export function getUsername(): string {
  try {
    return userInfo().username
  } catch {
    return process.env.USER ?? process.env.USERNAME ?? 'unknown'
  }
}
