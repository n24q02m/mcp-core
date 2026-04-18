import { beforeEach, describe, expect, it } from 'vitest'
import { clearMachineIdCacheForTesting, getMachineId, getUsername } from '../../src/storage/machine-id.js'

describe('getMachineId', () => {
  beforeEach(() => {
    clearMachineIdCacheForTesting()
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
