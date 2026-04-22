# CHANGELOG

<!-- version list -->

## v1.6.1 (2026-04-22)

### Bug Fixes

- Relax pydantic floor to 2.12.5 for cohere compatibility
  ([#73](https://github.com/n24q02m/mcp-core/pull/73),
  [`9ce0024`](https://github.com/n24q02m/mcp-core/commit/9ce002471ce4379a5cc47f2c3744adc8265eeb65))

- Relax pydantic to >=2.12.5 for cohere compatibility
  ([#73](https://github.com/n24q02m/mcp-core/pull/73),
  [`9ce0024`](https://github.com/n24q02m/mcp-core/commit/9ce002471ce4379a5cc47f2c3744adc8265eeb65))

- Use /authorize path in relay client URL to match server endpoint
  ([#73](https://github.com/n24q02m/mcp-core/pull/73),
  [`9ce0024`](https://github.com/n24q02m/mcp-core/commit/9ce002471ce4379a5cc47f2c3744adc8265eeb65))


## v1.6.0 (2026-04-22)

### Bug Fixes

- Update non-major dependencies
  ([`4c4dbd4`](https://github.com/n24q02m/mcp-core/commit/4c4dbd41c6914e0dcf6ff01d89ba22c38cf21b25))

- Use /authorize path in relay client URL to match server endpoint
  ([#72](https://github.com/n24q02m/mcp-core/pull/72),
  [`4d19190`](https://github.com/n24q02m/mcp-core/commit/4d19190b822e2a00ea1eb06445605bc59334e667))

### Chores

- **deps**: Update dependency @types/node to v25
  ([#58](https://github.com/n24q02m/mcp-core/pull/58),
  [`ad7ce6c`](https://github.com/n24q02m/mcp-core/commit/ad7ce6ca7d31b1ac5a9df042abdf0487a8e2662c))

- **deps**: Update dependency typescript to v6 ([#62](https://github.com/n24q02m/mcp-core/pull/62),
  [`654c7eb`](https://github.com/n24q02m/mcp-core/commit/654c7eb418431a2ded1189ae30555b7035575134))

### Features

- Batch random generation in passphrase creation
  ([#70](https://github.com/n24q02m/mcp-core/pull/70),
  [`50b194b`](https://github.com/n24q02m/mcp-core/commit/50b194bf622382e2836513693db70bf9a0b233ef))

- Improve credential form validation UX ([#71](https://github.com/n24q02m/mcp-core/pull/71),
  [`d94d2f5`](https://github.com/n24q02m/mcp-core/commit/d94d2f5344770457e92594546653ddabe696c65c))


## v1.5.1 (2026-04-21)

### Bug Fixes

- Add focus rings to credential form for WCAG 2.4.7
  ([`4ada9db`](https://github.com/n24q02m/mcp-core/commit/4ada9db1d377a7b26daf84bf5f4c6b8315e2fa0f))

- Bump actions/setup-node digest to 48b55a0
  ([`73ce205`](https://github.com/n24q02m/mcp-core/commit/73ce205a7eb20cb04af31b991c138f69900c71af))

- Bump step-security/harden-runner digest to 8d3c67d
  ([`f588094`](https://github.com/n24q02m/mcp-core/commit/f588094285a90a466de637d3023647b983d31fe6))


## v1.5.0 (2026-04-21)

### Bug Fixes

- Avoid relay session DELETE race that leaves browser UI stuck
  ([`7057e5c`](https://github.com/n24q02m/mcp-core/commit/7057e5c3d0503729621c3174303a3c45399b4347))

- Hoist invariant string transforms in config resolvers + native replaceAll
  ([`8d7b1a5`](https://github.com/n24q02m/mcp-core/commit/8d7b1a5f85724ca001098c4835fd42fc9886b581))

- Improve dark mode color contrast for accessibility
  ([`3f25033`](https://github.com/n24q02m/mcp-core/commit/3f25033e1f3a93a7c46b1362086ce7da1952d3f3))

- Remove AI traces (.jules / superpowers content — belongs in private n24q02m/.superpower repo)
  ([`e9e354b`](https://github.com/n24q02m/mcp-core/commit/e9e354b9586a66a5e751485882f01ca3c83a3c27))

- **auth**: Thread per-authorize-request sub through credential + step callbacks
  ([`3649aec`](https://github.com/n24q02m/mcp-core/commit/3649aecaab804ffc72290031ebbfe1b530e2149a))

- **deps**: Update env-paths to v4
  ([`6601e20`](https://github.com/n24q02m/mcp-core/commit/6601e202f03c9b3d77e2cd82fbd3922f256d485c))

- **deps**: Update step-security/harden-runner digest to 6c3c2f2
  ([`c5bc0f0`](https://github.com/n24q02m/mcp-core/commit/c5bc0f0be3175eff0a8076f7f1f69c3af5705f9f))

### Features

- **core-py**: Add start_local_server_background for stdio fallback
  ([`54081fb`](https://github.com/n24q02m/mcp-core/commit/54081fb0942914c1eca72b9e3df9e178f8e27256))


## v1.4.3 (2026-04-20)

### Bug Fixes

- Clear aria-busy on step-input reset to unblock chained submit
  ([`c70daf2`](https://github.com/n24q02m/mcp-core/commit/c70daf2525b9063f1f1314fda15ded1d5a4d4e6f))


## v1.4.2 (2026-04-20)

### Bug Fixes

- Use HTTP Basic auth for upstream OAuth token exchange
  ([`59bedb4`](https://github.com/n24q02m/mcp-core/commit/59bedb4544c0c9a3f3ec8b3b034fdcdef1c0fc1b))


## v1.4.1 (2026-04-20)

### Bug Fixes

- Parity GET / bootstrap redirect in delegated OAuth app (core-ts + core-py)
  ([`ea12dde`](https://github.com/n24q02m/mcp-core/commit/ea12dde3531a8e6b90c5dab14b6852617a961d49))


## v1.4.0 (2026-04-19)

### Bug Fixes

- Clickable local relay URL + failure state propagation
  ([#61](https://github.com/n24q02m/mcp-core/pull/61),
  [`57f8326`](https://github.com/n24q02m/mcp-core/commit/57f8326465d3700b61ef668e987d81386a40356e))

- Per-request transport in runLocalServer stateless HTTP
  ([`3f05744`](https://github.com/n24q02m/mcp-core/commit/3f057440110cacf8156c852fd472fab0c84e2398))

- Prevent token leakage via CLI arguments in stdio-proxy
  ([#13](https://github.com/n24q02m/mcp-core/pull/13),
  [`27da69d`](https://github.com/n24q02m/mcp-core/commit/27da69d7f38e14cdf18b25cd358f546a0ba15673))

### Chores

- **deps**: Update actions/create-github-app-token digest to 1b10c78
  ([#53](https://github.com/n24q02m/mcp-core/pull/53),
  [`f8d7264`](https://github.com/n24q02m/mcp-core/commit/f8d72644769744066a5989702800ab648d169947))

- **deps**: Update actions/upload-artifact digest to 043fb46
  ([#54](https://github.com/n24q02m/mcp-core/pull/54),
  [`23d04b4`](https://github.com/n24q02m/mcp-core/commit/23d04b4290e81c00b822b38c39a59f9094bb160a))

- **deps**: Update semgrep/semgrep docker digest to d7d67e1
  ([#55](https://github.com/n24q02m/mcp-core/pull/55),
  [`3748b02`](https://github.com/n24q02m/mcp-core/commit/3748b02da146216bd84a53b4a11bf8e14c432e03))

### Features

- Add ARIA accessibility states to credential forms
  ([#50](https://github.com/n24q02m/mcp-core/pull/50),
  [`03ca30a`](https://github.com/n24q02m/mcp-core/commit/03ca30ab4648d00335958269018d0fe825a1f9e2))

- Hoist Uint16Array allocation in generatePassphrase
  ([#49](https://github.com/n24q02m/mcp-core/pull/49),
  [`8109225`](https://github.com/n24q02m/mcp-core/commit/8109225dc837e4eee62dac94fb4ddbe19050216e))


## v1.3.0 (2026-04-18)

### Bug Fixes

- Add caching to get_machine_id ([#16](https://github.com/n24q02m/mcp-core/pull/16),
  [`2f02117`](https://github.com/n24q02m/mcp-core/commit/2f02117983a4d8ffe382f1d46b20aa61c2909d43))

- Add unit tests for SqliteUserStore ([#15](https://github.com/n24q02m/mcp-core/pull/15),
  [`0070834`](https://github.com/n24q02m/mcp-core/commit/0070834bda3e80aad093a0df2972cc8cd96c17a4))

- Eliminate polynomial ReDoS in Bearer auth regex
  ([`69f5637`](https://github.com/n24q02m/mcp-core/commit/69f563775de494f5887870aa8959a9317eda5e24))

- Improve LifecycleLock error handling and add tests for error paths
  ([#23](https://github.com/n24q02m/mcp-core/pull/23),
  [`2213053`](https://github.com/n24q02m/mcp-core/commit/221305340ec1d7b2b56d4f7d4b9c43ccbce9a06c))

- Move better-godot-mcp to TS downstream in auto-issue step
  ([`c4f9343`](https://github.com/n24q02m/mcp-core/commit/c4f9343c1f6b2cf24035f0c1706a1078378f3d9e))

- Replace hardcoded client id and fix CI failures
  ([#52](https://github.com/n24q02m/mcp-core/pull/52),
  [`e49d244`](https://github.com/n24q02m/mcp-core/commit/e49d244dc85020de81c9331689e315db5c7b5328))

- Replace hardcoded client id and fix CI failures
  ([#26](https://github.com/n24q02m/mcp-core/pull/26),
  [`499ebee`](https://github.com/n24q02m/mcp-core/commit/499ebee3c2563b77c0fb5a8e746e42de4b161448))

- Replace hardcoded client id in schema tests ([#52](https://github.com/n24q02m/mcp-core/pull/52),
  [`e49d244`](https://github.com/n24q02m/mcp-core/commit/e49d244dc85020de81c9331689e315db5c7b5328))

- Replace hardcoded client id in schema tests ([#26](https://github.com/n24q02m/mcp-core/pull/26),
  [`499ebee`](https://github.com/n24q02m/mcp-core/commit/499ebee3c2563b77c0fb5a8e746e42de4b161448))

- Replace hardcoded client id in schema tests and fix flaky passphrase test
  ([#52](https://github.com/n24q02m/mcp-core/pull/52),
  [`e49d244`](https://github.com/n24q02m/mcp-core/commit/e49d244dc85020de81c9331689e315db5c7b5328))

- Replace hardcoded client id in schema tests and fix flaky passphrase test
  ([#26](https://github.com/n24q02m/mcp-core/pull/26),
  [`499ebee`](https://github.com/n24q02m/mcp-core/commit/499ebee3c2563b77c0fb5a8e746e42de4b161448))

- Split long validateSchema into smaller validation functions
  ([#34](https://github.com/n24q02m/mcp-core/pull/34),
  [`4029bd5`](https://github.com/n24q02m/mcp-core/commit/4029bd52fa7e3842996b31c099920eb0e16aa051))

- Untrack .jules/.Jules AI trace files from public repo
  ([`2ae6292`](https://github.com/n24q02m/mcp-core/commit/2ae62921304c0552a9a884b503dc77834686d708))

- 🛡️ Sentinel: Fix command injection in tryOpenBrowser
  ([#36](https://github.com/n24q02m/mcp-core/pull/36),
  [`a829a5f`](https://github.com/n24q02m/mcp-core/commit/a829a5f340f9188ec6596557767fc4d89cca1c30))

### Features

- [TEST] Missing tests for OAuthProvider class ([#33](https://github.com/n24q02m/mcp-core/pull/33),
  [`8f20cae`](https://github.com/n24q02m/mcp-core/commit/8f20caee03fde563207d072fcf30a1b9c835eace))

- Add authScope/auth_scope hook to runLocalServer for JWT claims propagation
  ([#52](https://github.com/n24q02m/mcp-core/pull/52),
  [`e49d244`](https://github.com/n24q02m/mcp-core/commit/e49d244dc85020de81c9331689e315db5c7b5328))

- Add delegated_oauth option to run_local_server in core-py
  ([#52](https://github.com/n24q02m/mcp-core/pull/52),
  [`e49d244`](https://github.com/n24q02m/mcp-core/commit/e49d244dc85020de81c9331689e315db5c7b5328))

- Add delegatedOAuth option to runLocalServer in core-ts
  ([#52](https://github.com/n24q02m/mcp-core/pull/52),
  [`e49d244`](https://github.com/n24q02m/mcp-core/commit/e49d244dc85020de81c9331689e315db5c7b5328))

- Add tests for Python JWTIssuer class ([#21](https://github.com/n24q02m/mcp-core/pull/21),
  [`6c45fe8`](https://github.com/n24q02m/mcp-core/commit/6c45fe81886198e213f2efc8a26364275fb42eca))

- Add tests for SqliteUserStore and validate master_key length
  ([#14](https://github.com/n24q02m/mcp-core/pull/14),
  [`325b48c`](https://github.com/n24q02m/mcp-core/commit/325b48c2cfdd18f977fcc80da78a45fc757f883f))

- Cache `getMachineId` to reduce redundant OS command executions
  ([#48](https://github.com/n24q02m/mcp-core/pull/48),
  [`2dde3c7`](https://github.com/n24q02m/mcp-core/commit/2dde3c7b55c015ef390bdc67555adc0e3ef27761))

- Expose createDelegatedOAuthApp in core-ts + core-py root indexes
  ([#52](https://github.com/n24q02m/mcp-core/pull/52),
  [`e49d244`](https://github.com/n24q02m/mcp-core/commit/e49d244dc85020de81c9331689e315db5c7b5328))

- Phase L2 delegated OAuth primitives + integration hooks
  ([#52](https://github.com/n24q02m/mcp-core/pull/52),
  [`e49d244`](https://github.com/n24q02m/mcp-core/commit/e49d244dc85020de81c9331689e315db5c7b5328))

### Testing

- Add missing tests for JWTIssuer class ([#20](https://github.com/n24q02m/mcp-core/pull/20),
  [`f24f53c`](https://github.com/n24q02m/mcp-core/commit/f24f53cbb98c4a6efc94940464ff388d29718290))


## v1.2.0 (2026-04-17)

### Bug Fixes

- Pin authlib>=1.6.11 to address CVE (CSRF via cache)
  ([`04be55f`](https://github.com/n24q02m/mcp-core/commit/04be55f9addaa18e774515d39c7d5c4de5dd1590))

### Features

- Auto-create downstream bump issues on stable release
  ([`1a423e8`](https://github.com/n24q02m/mcp-core/commit/1a423e8686102261b475532bedd71e9aa44ebfb9))


## v1.1.1 (2026-04-17)

### Bug Fixes

- Honor PUBLIC_URL env for OAuth metadata issuer
  ([`2d3f8d8`](https://github.com/n24q02m/mcp-core/commit/2d3f8d8ff814fc70a32cc79c7aaf4b1523c9ec9d))


## v1.1.1-beta.1 (2026-04-17)

### Bug Fixes

- Add diacritic preservation pre-commit hook ([#44](https://github.com/n24q02m/mcp-core/pull/44),
  [`4c94db9`](https://github.com/n24q02m/mcp-core/commit/4c94db97a0b591ab6e474ef174be60cb6837ab30))

- Bump authlib to 1.6.11 for CSRF cache bypass (GHSA-jj8c-mmj3-mmgv)
  ([`c9d9c8b`](https://github.com/n24q02m/mcp-core/commit/c9d9c8baf97642f0782276e13b6469a25c83242f))

- Drop unused llama-cpp-python to remove diskcache CVE-2025-69872
  ([#45](https://github.com/n24q02m/mcp-core/pull/45),
  [`5715187`](https://github.com/n24q02m/mcp-core/commit/571518710c1f7a2f64b1d8dfc418b488c9d6a72a))

- Ignore coverage.xml and htmlcov artifacts ([#43](https://github.com/n24q02m/mcp-core/pull/43),
  [`03f9af5`](https://github.com/n24q02m/mcp-core/commit/03f9af5bfc7fc44ea4ff03680cd920a4c99137ff))

- Ignore coverage.xml and htmlcov artifacts
  ([`eb25182`](https://github.com/n24q02m/mcp-core/commit/eb2518260d54c286a25ce0cb267f26825cbefc0a))

- Sync docs with Phase M completion reality ([#43](https://github.com/n24q02m/mcp-core/pull/43),
  [`03f9af5`](https://github.com/n24q02m/mcp-core/commit/03f9af5bfc7fc44ea4ff03680cd920a4c99137ff))

### Performance Improvements

- Cache derived file key in config_file.py ([#12](https://github.com/n24q02m/mcp-core/pull/12),
  [`d582afc`](https://github.com/n24q02m/mcp-core/commit/d582afcb47ff1a6c975d346b148bb4622401e948))


## v1.1.0 (2026-04-17)

### Chores

- Ignore AI assistant traces
  ([`0c11ad8`](https://github.com/n24q02m/mcp-core/commit/0c11ad89221a8cb122f0f7dcfe0b8c283e2e32a8))

### Features

- Add host option to Python run_local_server
  ([`8b96267`](https://github.com/n24q02m/mcp-core/commit/8b9626745d0b64266bd8b4661754c42cbfb20e04))


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
