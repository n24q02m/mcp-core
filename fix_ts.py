path = 'packages/core-ts/tests/transport/local-server.test.ts'
content = open(path).read()
content = content.replace("expect, it } from 'vitest'", "expect, it, vi } from 'vitest'")
content = content.replace(
    "import { type HttpServerHandle, runHttpServer } from '../../src/transport/local-server.js'",
    "import { type HttpServerHandle, runHttpServer } from '../../src/transport/local-server.js'\n\nvi.mock('../../src/relay/browser.js', () => ({\n  tryOpenBrowser: vi.fn().mockResolvedValue(true)\n}))"
)
content = content.replace("sessionId!", "(sessionId as string)")
open(path, 'w').write(content)
