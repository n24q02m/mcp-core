import os

def fix_file(path, replacements):
    if not os.path.exists(path): return
    content = open(path).read()
    for old, new in replacements.items():
        content = content.replace(old, new)
    open(path, 'w').write(content)

# tests/transport/local-server.test.ts
fix_file('tests/transport/local-server.test.ts', {
    "import { type HttpServerHandle, runHttpServer } from '../../src/transport/local-server.js'":
    "import { type HttpServerHandle, runHttpServer } from '../../src/transport/local-server.js'\n\nvi.mock('../../src/relay/browser.js', () => ({\n  tryOpenBrowser: vi.fn().mockResolvedValue(true)\n}))",
    "expect, it }": "expect, it, vi }",
    "'mcp-session-id': sessionId!": "'mcp-session-id': sessionId as string"
})

# tests/storage/setup-complete-flag.test.ts
fix_file('tests/storage/setup-complete-flag.test.ts', {
    "saved![SETUP_COMPLETE_KEY]": "saved?.[SETUP_COMPLETE_KEY]",
    "saved!.API_KEY": "saved?.API_KEY"
})

# tests/oauth/provider.test.ts
fix_file('tests/oauth/provider.test.ts', {
    "(cache as any).cache": "(cache as unknown as { cache: any }).cache",
    "(provider as any).cache": "(provider as unknown as { cache: any }).cache",
    "(providerWithCache as any).cache": "(providerWithCache as unknown as { cache: any }).cache",
})
