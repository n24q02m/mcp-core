import { describe, expect, it, vi } from 'vitest'
import { generatePassphrase } from '../../src/relay/client.js'
import { WORDLIST } from '../../src/relay/wordlist.js'

describe('generatePassphrase rejection sampling coverage', () => {
  it('should trigger rejection sampling when a biased value is generated', () => {
    // max = 62208
    const max = Math.floor(0x10000 / WORDLIST.length) * WORDLIST.length

    let callCount = 0
    vi.spyOn(crypto, 'getRandomValues').mockImplementation((buffer) => {
      callCount++
      if (callCount === 1) {
        // Initial buffer (wordCount = 1)
        ;(buffer as Uint16Array)[0] = max + 1 // Biased value
      } else {
        // Fallback buffer
        ;(buffer as Uint16Array)[0] = 123 // Valid value
      }
      return buffer
    })

    const passphrase = generatePassphrase(1)

    expect(crypto.getRandomValues).toHaveBeenCalledTimes(2)
    expect(passphrase).toBe(WORDLIST[123 % WORDLIST.length])

    vi.restoreAllMocks()
  })

  it('should resample multiple times if needed', () => {
    const max = Math.floor(0x10000 / WORDLIST.length) * WORDLIST.length

    let callCount = 0
    vi.spyOn(crypto, 'getRandomValues').mockImplementation((buffer) => {
      callCount++
      if (callCount === 1) {
        // Initial buffer
        ;(buffer as Uint16Array)[0] = max // Biased
      } else if (callCount === 2) {
        // First resample
        ;(buffer as Uint16Array)[0] = max + 5 // Still biased
      } else {
        // Second resample
        ;(buffer as Uint16Array)[0] = 456 // Valid
      }
      return buffer
    })

    const passphrase = generatePassphrase(1)

    expect(crypto.getRandomValues).toHaveBeenCalledTimes(3)
    expect(passphrase).toBe(WORDLIST[456 % WORDLIST.length])

    vi.restoreAllMocks()
  })
})
