import { describe, expect, it, vi } from 'vitest'
import { generatePassphrase } from '../../src/relay/client.js'
import { WORDLIST } from '../../src/relay/wordlist.js'

describe('generatePassphrase rejection sampling', () => {
  it('should resample when a value is above the threshold', () => {
    const max = Math.floor(0x10000 / WORDLIST.length) * WORDLIST.length
    // max should be 62208 given WORDLIST.length is 7776
    expect(max).toBe(62208)

    // Mock crypto.getRandomValues
    const getRandomValuesSpy = vi.spyOn(crypto, 'getRandomValues')

    let callCount = 0
    getRandomValuesSpy.mockImplementation((buffer) => {
      callCount++
      if (buffer instanceof Uint16Array) {
        if (buffer.length === 4) {
          // Initial batch for 4 words
          buffer[0] = 63000 // Rejected (>= 62208)
          buffer[1] = 1000 // Accepted
          buffer[2] = 2000 // Accepted
          buffer[3] = 3000 // Accepted
        } else if (buffer.length === 1) {
          // Fallback calls
          if (callCount === 2) {
            buffer[0] = 64000 // Rejected again (>= 62208)
          } else if (callCount === 3) {
            buffer[0] = 500 // Finally accepted
          }
        }
      }
      return buffer
    })

    const passphrase = generatePassphrase(4)

    // Word 0: 63000 (rejected) -> 64000 (rejected) -> 500 (accepted)
    // Word 1: 1000
    // Word 2: 2000
    // Word 3: 3000

    const expectedWords = [
      WORDLIST[500 % WORDLIST.length],
      WORDLIST[1000 % WORDLIST.length],
      WORDLIST[2000 % WORDLIST.length],
      WORDLIST[3000 % WORDLIST.length]
    ]

    expect(passphrase).toBe(expectedWords.join('-'))

    // 1 (initial) + 2 (fallbacks) = 3 calls
    expect(callCount).toBe(3)

    getRandomValuesSpy.mockRestore()
  })
})
