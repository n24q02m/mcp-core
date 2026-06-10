import sys

path = 'packages/core-ts/tests/relay/client.test.ts'
with open(path, 'r') as f:
    content = f.read()

import re

# Fix the TypeScript errors by casting buffer
old_code = """    const getRandomValuesSpy = vi.spyOn(crypto, 'getRandomValues').mockImplementation((buffer) => {
      if (buffer.length === 16) {
        // Fallback buffer refill
        buffer.fill(2000) // All valid
      } else {
        // Primary buffer or others
        buffer.fill(65000) // All rejected
      }
      return buffer
    })"""

new_code = """    const getRandomValuesSpy = vi.spyOn(crypto, 'getRandomValues').mockImplementation((buffer) => {
      const typedBuffer = buffer as Uint16Array
      if (typedBuffer.length === 16) {
        // Fallback buffer refill
        typedBuffer.fill(2000) // All valid
      } else {
        // Primary buffer or others
        typedBuffer.fill(65000) // All rejected
      }
      return buffer
    })"""

if old_code in content:
    fixed_content = content.replace(old_code, new_code)
    with open(path, 'w') as f:
        f.write(fixed_content)
    print('Fixed TS errors')
else:
    print('Could not find old code')
