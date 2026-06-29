import { homedir } from 'node:os'
import { beforeEach, describe, expect, it } from 'vitest'
import { getHomeDir, setHomeDirForTesting } from '../../src/storage/home-dir.js'

describe('home-dir', () => {
  beforeEach(() => {
    setHomeDirForTesting(null)
  })

  it('returns default homedir when no override is set', () => {
    expect(getHomeDir()).toBe(homedir())
  })

  it('returns override value when set', () => {
    const override = '/tmp/fake-home'
    setHomeDirForTesting(override)
    expect(getHomeDir()).toBe(override)
  })

  it('resets to default homedir when override is cleared', () => {
    const override = '/tmp/fake-home'
    setHomeDirForTesting(override)
    expect(getHomeDir()).toBe(override)

    setHomeDirForTesting(null)
    expect(getHomeDir()).toBe(homedir())
  })
})
