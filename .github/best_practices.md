# Style Guide - mcp-core

## Architecture
Unified MCP Streamable HTTP 2025-11-25 transport, OAuth 2.1 Authorization

## TypeScript
- Runtime: Node.js 24+ via `mise`
- Package manager: `bun` (lockfile committed: `bun.lock`)
- Module: ESM (`"type": "module"` in package.json)
- TS config: strict, target es2021, module es2022, moduleResolution Bundler
- Import: `.js` extension required (ESM); `import type` for types; `node:` prefix for builtins

## Lint + Format
- `biome` (single tool replaces ESLint + Prettier)
- 2 spaces, line width 120, single quotes, semicolons as needed, no trailing commas
- Run: `bun run check` (lint + format check + tsc --noEmit)

## Tests
- `vitest` (NOT `bun test` — use `bun run test` to delegate to vitest)
- Co-located test files: `errors.test.ts` next to `errors.ts`
- Coverage target: ≥ 95% on `src/`

## Code Patterns
- Composite tool pattern: `async function toolName(client, input: TypedInput): Promise<any>`
- Error handling: custom Error class + `withErrorHandling()` HOF
- `noExplicitAny`: off (when interfacing with untyped APIs)
- `import type { Foo }` separated from value imports

## CI/CD
- CI: `bun run check && bun run test`
- CD: workflow_dispatch, PSR v10 → npm publish + Docker multi-arch + MCP Registry (if MCP server)

## Pre-commit
- biome (`check --write`)
- tsc --noEmit (type check)
- bun run test
- commit-msg: enforce `feat:` / `fix:` prefix
