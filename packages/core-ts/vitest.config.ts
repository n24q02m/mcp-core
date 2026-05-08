import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // CI Windows runners are slow on `runHttpServer` integration tests —
    // the delegated-mode test ran 5008ms locally, 30s+ on hosted Windows.
    // 60s gives generous margin without masking real hangs.
    testTimeout: 60000,
    hookTimeout: 60000
  }
})
