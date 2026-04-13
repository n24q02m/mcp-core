# CHANGELOG

<!-- version list -->

## v1.0.0 (2026-04-13)

### Bug Fixes

- Cache PBKDF2 derived key for config performance
  ([`fe14185`](https://github.com/n24q02m/mcp-core/commit/fe14185a7acb1371621be41a3b627c197f5474d8))

- Credential form accessibility (aria-describedby/invalid/busy)
  ([`85bd3f5`](https://github.com/n24q02m/mcp-core/commit/85bd3f5d66b20abe0abd6dc278fd6c1704f241d2))

- Resolve type checking errors in Python files
  ([`fe14185`](https://github.com/n24q02m/mcp-core/commit/fe14185a7acb1371621be41a3b627c197f5474d8))

- Thread-based stdin reader + Accept header in stdio-proxy
  ([`044acec`](https://github.com/n24q02m/mcp-core/commit/044acec926404360cd20cf1641ec2eb4ddd7355a))

### Features

- Cache derived key to speed up config read/writes
  ([`fe14185`](https://github.com/n24q02m/mcp-core/commit/fe14185a7acb1371621be41a3b627c197f5474d8))


## v1.0.0-beta.4 (2026-04-13)

### Bug Fixes

- Add README.md to package directories for local editable installs
  ([`727fe68`](https://github.com/n24q02m/mcp-core/commit/727fe68edf939ab52103b6e9d674bd8626b7b822))

- Address code review issues for /otp endpoint
  ([`0ea1163`](https://github.com/n24q02m/mcp-core/commit/0ea116388b3c3b15c5cf235ab14d973f770434ba))

- Apply ty lenient rules on core-py matching wet/mnemo/crg/telegram
  ([`2076569`](https://github.com/n24q02m/mcp-core/commit/207656941afe405f00473f5efcc24e2e14ffd43c))

- Decouple writeConfig from process exit to unblock OAuth device code
  ([`ad8f9ee`](https://github.com/n24q02m/mcp-core/commit/ad8f9ee10d88862a16ada0fac4f7e678df96efec))

- Dedupe repeat try_open_browser calls for the same URL
  ([`f997120`](https://github.com/n24q02m/mcp-core/commit/f997120071ae44e8e0aca021738f648e6b16f218))

- Forward mark_setup_complete from OAuth app to combined app
  ([`8e168e2`](https://github.com/n24q02m/mcp-core/commit/8e168e25d7f12dfde841e14e0ee4ac3503f7ba1f))

- Improve multi-step form accessibility and test coverage
  ([`0ecfdc1`](https://github.com/n24q02m/mcp-core/commit/0ecfdc19605e98d6caddabd688ca360d19d3ac5b))

- Prevent write_config auto-restart from killing HTTP server
  ([`d024575`](https://github.com/n24q02m/mcp-core/commit/d024575bf9861f75de8e840005c5d7d7ff3ef125))

- Remove auto-open browser on startup (bare /authorize returns 400)
  ([`661d95b`](https://github.com/n24q02m/mcp-core/commit/661d95b92c84bfb34ad5554fb5184a9fc4635b1d))

- Use uvicorn.Server.serve() instead of uvicorn.run() to avoid nested event loop
  ([`92b973c`](https://github.com/n24q02m/mcp-core/commit/92b973ca9bc19dda00090eb796ffaa9d344d26fb))

### Features

- Add /otp endpoint for multi-step auth in local OAuth AS
  ([`a28bf58`](https://github.com/n24q02m/mcp-core/commit/a28bf588b671e9d8d0e542096d22c82afe187566))

- Add /setup-status endpoint and GDrive completion polling in form
  ([`fcbc86b`](https://github.com/n24q02m/mcp-core/commit/fcbc86b181b83081c737f18f7973ec583a705f42))

- Add auth module with dark-themed credential form HTML renderer
  ([`c574be8`](https://github.com/n24q02m/mcp-core/commit/c574be8b5ecd7065c1cb58caf4491e565a34d968))

- Add credential form HTML renderer for core-ts
  ([`4589c08`](https://github.com/n24q02m/mcp-core/commit/4589c08d0bc0195c9fc712d33d85aa8ff905a9af))

- Add customCredentialFormHtml hook for consumer-provided form UX
  ([`728a5d8`](https://github.com/n24q02m/mcp-core/commit/728a5d816e49083f6633939b67dc187a1f061b77))

- Add delegated OAuth provider for device code and redirect flows
  ([`ad084c5`](https://github.com/n24q02m/mcp-core/commit/ad084c531fab66f896c35a71bf64cda02cff7352))

- Add internal HTTP router utility for core-ts auth
  ([`3512fda`](https://github.com/n24q02m/mcp-core/commit/3512fda6520613df6a72b96c52559e44efaedebf))

- Add local OAuth 2.1 AS app for core-ts
  ([`962a003`](https://github.com/n24q02m/mcp-core/commit/962a003ed8c8e05b43606c8c397c0aa84221dc62))

- Add local OAuth 2.1 Authorization Server Starlette app
  ([`d48c34c`](https://github.com/n24q02m/mcp-core/commit/d48c34c7d924bb94892672914069641308ef839a))

- Add local server entry point combining OAuth AS + MCP transport
  ([`01bdd7b`](https://github.com/n24q02m/mcp-core/commit/01bdd7bdffd3ee5f12a3b965c5b158105875bf3d))

- Add OAuth 2.1 well-known metadata generators (RFC 8414 + RFC 9728)
  ([`57154f7`](https://github.com/n24q02m/mcp-core/commit/57154f7109fb2cfa98dd3aaf7d587dbf28a6b0f8))

- Add runLocalServer entry point composing OAuth AS + MCP transport
  ([`c64b13a`](https://github.com/n24q02m/mcp-core/commit/c64b13a7ec09a2889c44d6c5b806b600df7311d8))

- Add setup_complete_hook to run_local_server
  ([`cd1f808`](https://github.com/n24q02m/mcp-core/commit/cd1f808e695bdb147e14eeb4895af7ed8e86837e))

- Add well-known OAuth metadata generators for core-ts
  ([`188da7f`](https://github.com/n24q02m/mcp-core/commit/188da7f198ee66a831805119bdf71b3d8766b83e))

- Extend credential form JS with multi-step OTP and password input
  ([`44a646e`](https://github.com/n24q02m/mcp-core/commit/44a646eb90da6f088dc19b307c96a2f1c194c186))

- Forward on_step_submitted callback through local server entry point
  ([`11f0cb9`](https://github.com/n24q02m/mcp-core/commit/11f0cb997340ebd450e31e4daa7afd6ae95e2eae))

- Handle next_step type=info in credential form
  ([`bc8ed03`](https://github.com/n24q02m/mcp-core/commit/bc8ed03f7e1b9687fa0f956858285e542f4b8850))

- Support async callbacks in local OAuth app
  ([`388b269`](https://github.com/n24q02m/mcp-core/commit/388b269decb261a4f8c16d0e14d418e9acab6752))

- Support next_step in OAuth credential form for GDrive device code
  ([`24587d6`](https://github.com/n24q02m/mcp-core/commit/24587d632bd63e22a9c500e429ae5b2f36259498))

- Update on_credentials_saved type to return optional dict
  ([`a16b0ef`](https://github.com/n24q02m/mcp-core/commit/a16b0efe86edcd790e147a83da6187d9422ba0b2))


## v1.0.0-beta.3 (2026-04-12)

### Bug Fixes

- Revert incorrect NPM_TOKEN env in CD workflow
  ([`3d6dea9`](https://github.com/n24q02m/mcp-core/commit/3d6dea93f80c34fa35722252cdf26ddb78a0352d))


## v1.0.0-beta.2 (2026-04-12)

### Bug Fixes

- Resolve pyproject readme path and npm auth for CD publishing
  ([`96618d0`](https://github.com/n24q02m/mcp-core/commit/96618d0dacd24a94e46f1edaa1b4ec8db3a75d79))


## v1.0.0-beta.1 (2026-04-12)

- Initial Release
