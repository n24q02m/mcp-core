import * as child_process from 'node:child_process'
import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { clearMachineIdCacheForTesting, getMachineId, getUsername } from '../../src/storage/machine-id.js'

describe('getMachineId', () => {
  beforeEach(() => {
    clearMachineIdCacheForTesting()
    vi.restoreAllMocks()
  })

  it('returns a non-empty string', async () => {
    const id = await getMachineId()
    expect(id).toBeTruthy()
    expect(typeof id).toBe('string')
    expect(id.length).toBeGreaterThan(0)
  })

  it('returns consistent value on consecutive calls', async () => {
    const id1 = await getMachineId()
    const id2 = await getMachineId()
    expect(id1).toBe(id2)
  })

  it('caches the result and only calls underlying OS methods once', async () => {
    // Mock OS/FS calls based on platform to ensure we're tracking the right one
    const readFileSpy = vi.spyOn(fs, 'readFile').mockResolvedValue('test-machine-id')
    const execFileSpy = vi.spyOn(child_process, 'execFile').mockImplementation((...args: any[]) => {
      const callback = args[args.length - 1]
      callback(null, { stdout: '"IOPlatformUUID" = "test-uuid"\nMachineGuid REG_SZ test-guid' }, '')
      return {} as any
    })
    const networkInterfacesSpy = vi.spyOn(os, 'networkInterfaces').mockReturnValue({
      eth0: [
        { mac: '00:11:22:33:44:55', internal: false, family: 'IPv4', address: '127.0.0.1', netmask: '255.255.255.0' }
      ]
    } as any)

    // First call
    await getMachineId()

    // Second call
    await getMachineId()

    const totalCalls =
      readFileSpy.mock.calls.length + execFileSpy.mock.calls.length + networkInterfacesSpy.mock.calls.length
    expect(totalCalls).toBe(1)
  })
})

describe('getUsername', () => {
  it('returns a non-empty string', () => {
    const username = getUsername()
    expect(username).toBeTruthy()
    expect(typeof username).toBe('string')
    expect(username.length).toBeGreaterThan(0)
  })

  it('matches current OS user', () => {
    const username = getUsername()
    const expected = process.env.USER ?? process.env.USERNAME
    if (expected) {
      expect(username).toBe(expected)
    }
  })
})
