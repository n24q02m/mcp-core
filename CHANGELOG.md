# CHANGELOG

<!-- version list -->

## v1.18.0-beta.21 (2026-06-29)

### Bug Fixes

- Add full test coverage for vectorize backend
  ([#540](https://github.com/n24q02m/mcp-core/pull/540),
  [`42f03c5`](https://github.com/n24q02m/mcp-core/commit/42f03c52a663d63ed9bfc920c97cc02da628d973))

- Add role=alert to credential form for a11y
  ([`1aa14ab`](https://github.com/n24q02m/mcp-core/commit/1aa14ab1910cc52cdec6ab630e38ac25b5811c62))

- Add test coverage (mcp-core)
  ([`197fba9`](https://github.com/n24q02m/mcp-core/commit/197fba93a72d251a7b6d84c03ce25edca0790807))

- Add test coverage (mcp-core)
  ([`794a583`](https://github.com/n24q02m/mcp-core/commit/794a5837cf2b3482ec6d9da492161c0ba5355b36))

- Add test coverage (mcp-core)
  ([`c3540e6`](https://github.com/n24q02m/mcp-core/commit/c3540e657d405b933bd7647bdb8e8f9b21bda51f))

- Add test coverage (mcp-core)
  ([`eb3d1a6`](https://github.com/n24q02m/mcp-core/commit/eb3d1a67ed45c158015eb9079e7c0f610a5d350c))

- Add test coverage (mcp-core)
  ([`ae6fc08`](https://github.com/n24q02m/mcp-core/commit/ae6fc08a06e71b8c3e4f3b6c0d56ee5dac43beb5))

- Add test coverage (mcp-core)
  ([`6a3a63f`](https://github.com/n24q02m/mcp-core/commit/6a3a63f6bf8593602b85f865ca2f4220872f53dc))

- Add X-Frame-Options DENY to all HTML responses to prevent clickjacking
  ([`f820433`](https://github.com/n24q02m/mcp-core/commit/f82043319c2877c4e92c7d619a68ef07521b0e91))

- Consolidate cache tests without coverage loss
  ([`11386e9`](https://github.com/n24q02m/mcp-core/commit/11386e9d9729abf653913e81d84ea81398de0219))

- Consolidate embedding-daemon backend tests
  ([`85937db`](https://github.com/n24q02m/mcp-core/commit/85937dbc40a1c17d268433a57a2e2e7c3d06a18b))

- Drop now-unused ty:ignore in llm/catalog after ty bump
  ([`0ea59a2`](https://github.com/n24q02m/mcp-core/commit/0ea59a2bd0316f378e8e3c040139a022206f56ea))

- Length-hiding timing-safe compare for PKCE challenge verification
  ([`59cc4ed`](https://github.com/n24q02m/mcp-core/commit/59cc4ed8130fa2c80923e6958d04c11b364bc339))

- Prune expired oauth entries in-place ([#549](https://github.com/n24q02m/mcp-core/pull/549),
  [`2db465e`](https://github.com/n24q02m/mcp-core/commit/2db465e0da5059a81501e5c7bf18f2e5e6c93c1a))

- Replace unsafe any casts with typed assertions in core-ts
  ([#557](https://github.com/n24q02m/mcp-core/pull/557),
  [`a28c990`](https://github.com/n24q02m/mcp-core/commit/a28c9905d27e7e7cbaf822e2a4c6f9b60755c778))

- Reset setup status via dict.fromkeys ([#542](https://github.com/n24q02m/mcp-core/pull/542),
  [`5593006`](https://github.com/n24q02m/mcp-core/commit/559300648ba06b58054a6418f059122a625ea87c))

- Update non-major dev dependencies + drop obsolete ty:ignore
  ([`0ea59a2`](https://github.com/n24q02m/mcp-core/commit/0ea59a2bd0316f378e8e3c040139a022206f56ea))

- **deps**: Update dawidd6/action-send-mail action to v18
  ([#563](https://github.com/n24q02m/mcp-core/pull/563),
  [`09f9a5f`](https://github.com/n24q02m/mcp-core/commit/09f9a5f23bc4f8198a2c792ef437884cbe07ffb0))

- **deps**: Update non-major dependencies
  ([`0ea59a2`](https://github.com/n24q02m/mcp-core/commit/0ea59a2bd0316f378e8e3c040139a022206f56ea))

- **deps**: Update semgrep/semgrep Docker digest to 06938c1
  ([#560](https://github.com/n24q02m/mcp-core/pull/560),
  [`034e9cb`](https://github.com/n24q02m/mcp-core/commit/034e9cba72e705c178888719a09e48201ed9cf98))


## v1.18.0-beta.20 (2026-06-23)

### Bug Fixes

- Apply ruff format to model-chain test file ([#527](https://github.com/n24q02m/mcp-core/pull/527),
  [`100d12c`](https://github.com/n24q02m/mcp-core/commit/100d12ce9f94460b939a7aff383cf368daa8a6b9))

- Keep relay model-chain search keyword after selecting a model
  ([#527](https://github.com/n24q02m/mcp-core/pull/527),
  [`100d12c`](https://github.com/n24q02m/mcp-core/commit/100d12ce9f94460b939a7aff383cf368daa8a6b9))

### Features

- Live Jina model catalog (keyless) for relay embed/rerank search
  ([#527](https://github.com/n24q02m/mcp-core/pull/527),
  [`100d12c`](https://github.com/n24q02m/mcp-core/commit/100d12ce9f94460b939a7aff383cf368daa8a6b9))

- Live provider catalog + normalized litellm + keep relay search keyword
  ([#527](https://github.com/n24q02m/mcp-core/pull/527),
  [`100d12c`](https://github.com/n24q02m/mcp-core/commit/100d12ce9f94460b939a7aff383cf368daa8a6b9))

- Merge live provider catalog + normalize bare litellm ids in relay dropdown
  ([#527](https://github.com/n24q02m/mcp-core/pull/527),
  [`100d12c`](https://github.com/n24q02m/mcp-core/commit/100d12ce9f94460b939a7aff383cf368daa8a6b9))


## v1.18.0-beta.19 (2026-06-22)

### Bug Fixes

- Extend OAuth refresh-token TTL to 1 year to stop re-auth tab-spam
  ([#525](https://github.com/n24q02m/mcp-core/pull/525),
  [`67d5565`](https://github.com/n24q02m/mcp-core/commit/67d5565eb64a1b4a1c84390aac89b450b8bc509b))

- Make model-chain catalog tests litellm-independent
  ([#524](https://github.com/n24q02m/mcp-core/pull/524),
  [`d76bac4`](https://github.com/n24q02m/mcp-core/commit/d76bac4a3541bf45dc06c80d1c2f1ebf4e267418))

- Search full model catalog in relay model-chain (generate task + un-sliced)
  ([#524](https://github.com/n24q02m/mcp-core/pull/524),
  [`d76bac4`](https://github.com/n24q02m/mcp-core/commit/d76bac4a3541bf45dc06c80d1c2f1ebf4e267418))


## v1.18.0-beta.18 (2026-06-22)

### Bug Fixes

- Document llm/chains/http modules and correct API-parity claim in README
  ([#519](https://github.com/n24q02m/mcp-core/pull/519),
  [`a60ba47`](https://github.com/n24q02m/mcp-core/commit/a60ba47bc311c9516d841e596a9a664632bb39d0))

- **deps**: Lock file maintenance ([#522](https://github.com/n24q02m/mcp-core/pull/522),
  [`56684ef`](https://github.com/n24q02m/mcp-core/commit/56684eff22fb0bfc75c3bd381392e9d75b516979))

- **deps**: Update actions/checkout action to v7
  ([#521](https://github.com/n24q02m/mcp-core/pull/521),
  [`746939c`](https://github.com/n24q02m/mcp-core/commit/746939cfa1b24fe816943c8a8cd6cd51cfadd7bd))

- **deps**: Update non-major dependencies ([#520](https://github.com/n24q02m/mcp-core/pull/520),
  [`fde4213`](https://github.com/n24q02m/mcp-core/commit/fde42133065e8945ff5c45534b0206fcef057c10))


## v1.18.0-beta.17 (2026-06-21)

### Bug Fixes

- Make relay model-chain a searchable combobox (free-text + catalog-backed)
  ([#518](https://github.com/n24q02m/mcp-core/pull/518),
  [`4285650`](https://github.com/n24q02m/mcp-core/commit/4285650dd14fdd874b88026c67a7779568f36af3))

- **a11y**: Add aria-hidden="true" to optional badges
  ([#516](https://github.com/n24q02m/mcp-core/pull/516),
  [`46c1a50`](https://github.com/n24q02m/mcp-core/commit/46c1a502e3d6b4d5a1100c575d5dffeacdecd4d2))

- **deps**: Update @types/node to v26 ([#511](https://github.com/n24q02m/mcp-core/pull/511),
  [`92ec965`](https://github.com/n24q02m/mcp-core/commit/92ec9653679025366d882aed84f1c0ca80866c8f))

- **deps**: Update non-major dependencies ([#510](https://github.com/n24q02m/mcp-core/pull/510),
  [`dd8e6f1`](https://github.com/n24q02m/mcp-core/commit/dd8e6f14d68a983cb0e316ccad4513ffc45a1f95))

- **deps**: Update semgrep/semgrep Docker digest to c180f0c
  ([#509](https://github.com/n24q02m/mcp-core/pull/509),
  [`a6b45b0`](https://github.com/n24q02m/mcp-core/commit/a6b45b0180b32db313bd1d90570d712f496518ca))

### Chores

- **deps**: Bump the uv group across 2 directories with 1 update
  ([#515](https://github.com/n24q02m/mcp-core/pull/515),
  [`4ecfcc4`](https://github.com/n24q02m/mcp-core/commit/4ecfcc484ea93abd767912adb472513cb4d2fa7d))

### Features

- Add role='alert' to transient server status box for accessibility
  ([#505](https://github.com/n24q02m/mcp-core/pull/505),
  [`151aa18`](https://github.com/n24q02m/mcp-core/commit/151aa18bb1025fda1301692d9d1553868811f16d))


## v1.18.0-beta.16 (2026-06-20)

### Bug Fixes

- Relock uv.lock self-version in the release build_command
  ([`cb432a2`](https://github.com/n24q02m/mcp-core/commit/cb432a2a4b3b1035c8ac460babdd3ed3fe738b57))


## v1.18.0-beta.15 (2026-06-19)

### Bug Fixes

- Sync uv.lock editable self-version to released 1.18.0b14
  ([`07db16e`](https://github.com/n24q02m/mcp-core/commit/07db16ebcaafbf225ca64dabb13e62333b8cddc6))


## v1.18.0-beta.14 (2026-06-19)

### Features

- Per-provider API key rotation on rate-limit (CSV multi-key)
  ([`6157e98`](https://github.com/n24q02m/mcp-core/commit/6157e981fae1a6abdc6d86a1f5ed2bf157d7f80a))


## v1.18.0-beta.13 (2026-06-19)

### Features

- Add capability provider-chain primitive + search-chain relay widget
  ([#506](https://github.com/n24q02m/mcp-core/pull/506),
  [`94cee14`](https://github.com/n24q02m/mcp-core/commit/94cee14e4f68bd680e667eb964a02a240e703113))


## v1.18.0-beta.12 (2026-06-18)

### Features

- Add derive_stable_sub helper for username-keyed subjects
  ([`b025ba3`](https://github.com/n24q02m/mcp-core/commit/b025ba3c27d0fcadeaa9781e8a82accb430f5a0d))

- Derive stable JWT sub from optional workspace username
  ([`b025ba3`](https://github.com/n24q02m/mcp-core/commit/b025ba3c27d0fcadeaa9781e8a82accb430f5a0d))

- Optional workspace-username field in default credential form
  ([`b025ba3`](https://github.com/n24q02m/mcp-core/commit/b025ba3c27d0fcadeaa9781e8a82accb430f5a0d))

- Thread stable_sub_enabled through run_http_server wrapper
  ([`508b1df`](https://github.com/n24q02m/mcp-core/commit/508b1dfa4ea9cdcccd0f01a62fa3db5b4dc2dd2a))

- Username-keyed stable subject for data-bearing local-form servers
  ([`b025ba3`](https://github.com/n24q02m/mcp-core/commit/b025ba3c27d0fcadeaa9781e8a82accb430f5a0d))


## v1.18.0-beta.11 (2026-06-18)

### Bug Fixes

- Add context-specific aria-labels to OAuth re-authorize buttons
  ([`4ca81f3`](https://github.com/n24q02m/mcp-core/commit/4ca81f3f59df5f225739b4bd23ef3d5d9f52ae1b))

- Add coverage for config_file legacy fallback, setup-complete flag, and reload-exit paths
  ([`bbf2d55`](https://github.com/n24q02m/mcp-core/commit/bbf2d55652caeb7b9bf30261eb92f6c42b9bc626))

- Add coverage for transport cache empty-list, corruption, and chmod paths
  ([`d026408`](https://github.com/n24q02m/mcp-core/commit/d026408006d0a18a116cd0382ce75c24c1f89af5))

- Add embedding-daemon API endpoint, version fallback, and entrypoint tests
  ([`d4cccc0`](https://github.com/n24q02m/mcp-core/commit/d4cccc0e97887f37edbac88d94632b4c4f0af605))

- Add idempotency test for release_session when no session is active
  ([`c96cd87`](https://github.com/n24q02m/mcp-core/commit/c96cd872c47ef2168543bc4a45e5bb5937e42cff))

- Add JWT rejection coverage for expired, cross-issuer, and malformed tokens in local-server
  ([`7054d11`](https://github.com/n24q02m/mcp-core/commit/7054d11343bddeaad9399385e37d250432768c97))

- Add rejection-sampling edge-case tests for generatePassphrase (core-ts)
  ([`2d7810b`](https://github.com/n24q02m/mcp-core/commit/2d7810b8224a33894b22f38243c8b8984e851b34))

- Align core-ts tools cache JSON keys to snake_case for core-py parity and add coverage
  ([`9f599b1`](https://github.com/n24q02m/mcp-core/commit/9f599b1a5522ec90cef81185080b06257f38b58a))

- Consolidate and extend local_oauth_app on_credentials_saved callback coverage
  ([`0b85d3c`](https://github.com/n24q02m/mcp-core/commit/0b85d3c1e7091b309d71879750add6e9f7368ac9))

- Cover _mark_config_setup_complete failure branches in local OAuth app
  ([`474611d`](https://github.com/n24q02m/mcp-core/commit/474611d25d0d6532e2bb5c4f55241dc4e66e7a97))

- Cover _open_in_powershell env inheritance, subprocess errors, and browser-open dedupe
  ([`a6cc789`](https://github.com/n24q02m/mcp-core/commit/a6cc78919257f33127651f4ac688c852b7af02dc))

- Cover best-effort cleanup in runHttpServer shutdown loop
  ([`7247de9`](https://github.com/n24q02m/mcp-core/commit/7247de90a7c9af68b111e47a869483870af8539e))

- Cover docstring {server_name} substitution branch in _build_open_relay_handler
  ([`0223179`](https://github.com/n24q02m/mcp-core/commit/02231798f2f1a7384aef9cdd51add8ee5d7c0555))

- Cover OSError/JSONDecodeError recovery paths in core-py session_lock
  ([`d0bb9d3`](https://github.com/n24q02m/mcp-core/commit/d0bb9d3bdc51cb4bde9d67356abf3f8f695e881b))

- Cover router internal error handling and default property fallbacks
  ([`cd1e7a7`](https://github.com/n24q02m/mcp-core/commit/cd1e7a701cc027db8de020bf2d07f0ca325b55f6))

- Harden cache_filename against path traversal (defense-in-depth)
  ([`098b550`](https://github.com/n24q02m/mcp-core/commit/098b55093be9c90cac20b393879bd5aefb6d10e6))

- Harden SqliteUserStore against invalid db paths with clearer init errors and tests
  ([`76f7b6d`](https://github.com/n24q02m/mcp-core/commit/76f7b6d9448c948b63a1feaba5b9eeefdb18bb92))

- Link form descriptions to inputs via aria-describedby in auth forms
  ([`f939c3f`](https://github.com/n24q02m/mcp-core/commit/f939c3f440b8e767b3b5b4937b7ff1e120dd61b5))

- Refresh lockfile (renovate maintenance)
  ([`21bc0c5`](https://github.com/n24q02m/mcp-core/commit/21bc0c5d78d2608fc21aa4e150300bb2bee1d43d))

- Update non-major dependencies
  ([`f29621f`](https://github.com/n24q02m/mcp-core/commit/f29621f9c719a2bb05abbfd335288967a987c49e))

### Features

- Add aria-describedby context to authentication forms
  ([`f939c3f`](https://github.com/n24q02m/mcp-core/commit/f939c3f440b8e767b3b5b4937b7ff1e120dd61b5))

### Testing

- Add comprehensive coverage for config_file.py
  ([`bbf2d55`](https://github.com/n24q02m/mcp-core/commit/bbf2d55652caeb7b9bf30261eb92f6c42b9bc626))


## v1.18.0-beta.10 (2026-06-17)

### Bug Fixes

- Allow underscore in per-plugin-store sub + harden cred-path validation
  ([#501](https://github.com/n24q02m/mcp-core/pull/501),
  [`d48bf5f`](https://github.com/n24q02m/mcp-core/commit/d48bf5f8d64318d0a68f422eb01649665f983e3c))

- Suppress false-positive raw-query SAST on D1 batch + format backend tests
  ([#497](https://github.com/n24q02m/mcp-core/pull/497),
  [`9a5f5ef`](https://github.com/n24q02m/mcp-core/commit/9a5f5eff658f195c3b235658f54f52d2d438bd56))


## v1.18.0-beta.9 (2026-06-16)

### Features

- Promote D1Backend + VectorizeBackend into mcp-core storage
  ([#496](https://github.com/n24q02m/mcp-core/pull/496),
  [`6d22bca`](https://github.com/n24q02m/mcp-core/commit/6d22bcab6142da7b8637941dde3df62de7d139cc))


## v1.18.0-beta.8 (2026-06-16)

### Features

- StringSession store + save-on-change session for serverless Telethon
  ([#495](https://github.com/n24q02m/mcp-core/pull/495),
  [`c77ba0c`](https://github.com/n24q02m/mcp-core/commit/c77ba0c6ba820c46151c912c981f92e914b75cfc))


## v1.18.0-beta.7 (2026-06-15)

### Bug Fixes

- Expose storage barrel on the ./storage subpath for CF backends
  ([#494](https://github.com/n24q02m/mcp-core/pull/494),
  [`b090e27`](https://github.com/n24q02m/mcp-core/commit/b090e270545a78ac327fe1d873e1c6e81386c553))


## v1.18.0-beta.6 (2026-06-15)

### Bug Fixes

- Correct storage and auth module descriptions in README
  ([`f06502d`](https://github.com/n24q02m/mcp-core/commit/f06502d010cfa5bf62c435403938e2b383b11804))

### Features

- CfKvBackend.ready() readiness probe for CF outbound-interception race
  ([#493](https://github.com/n24q02m/mcp-core/pull/493),
  [`b041293`](https://github.com/n24q02m/mcp-core/commit/b0412938209ee321c5582ee88239da11eb52afbf))


## v1.18.0-beta.5 (2026-06-14)

### Features

- PerPluginStore token sub-key + LocalFs tokens namespace
  ([#489](https://github.com/n24q02m/mcp-core/pull/489),
  [`c77dd65`](https://github.com/n24q02m/mcp-core/commit/c77dd654c9fcf848d848723d3dcca8ed82b6fb98))


## v1.18.0-beta.4 (2026-06-14)

### Bug Fixes

- Make CfKvBackend fail loud on non-404 HTTP errors
  ([#488](https://github.com/n24q02m/mcp-core/pull/488),
  [`b720d5d`](https://github.com/n24q02m/mcp-core/commit/b720d5d3ca604dc5d416593c660be5ea4f313491))

- Use httpx instead of urllib in CfKvBackend HTTP client
  ([#488](https://github.com/n24q02m/mcp-core/pull/488),
  [`b720d5d`](https://github.com/n24q02m/mcp-core/commit/b720d5d3ca604dc5d416593c660be5ea4f313491))

- Validate MCP_KV_BASE_URL and cover CfKvBackend error paths
  ([#488](https://github.com/n24q02m/mcp-core/pull/488),
  [`b720d5d`](https://github.com/n24q02m/mcp-core/commit/b720d5d3ca604dc5d416593c660be5ea4f313491))

- Validate MCP_KV_BASE_URL in core-py for ts parity
  ([#488](https://github.com/n24q02m/mcp-core/pull/488),
  [`b720d5d`](https://github.com/n24q02m/mcp-core/commit/b720d5d3ca604dc5d416593c660be5ea4f313491))

- Validate path components in LocalFsBackend to block traversal
  ([#488](https://github.com/n24q02m/mcp-core/pull/488),
  [`b720d5d`](https://github.com/n24q02m/mcp-core/commit/b720d5d3ca604dc5d416593c660be5ea4f313491))

### Features

- Add CfKvBackend HTTP credential backend in core-py
  ([#488](https://github.com/n24q02m/mcp-core/pull/488),
  [`b720d5d`](https://github.com/n24q02m/mcp-core/commit/b720d5d3ca604dc5d416593c660be5ea4f313491))

- Add CredentialBackend protocol and InMemoryBackend in core-py
  ([#488](https://github.com/n24q02m/mcp-core/pull/488),
  [`b720d5d`](https://github.com/n24q02m/mcp-core/commit/b720d5d3ca604dc5d416593c660be5ea4f313491))

- Add LocalFsBackend preserving on-disk credential layout
  ([#488](https://github.com/n24q02m/mcp-core/pull/488),
  [`b720d5d`](https://github.com/n24q02m/mcp-core/commit/b720d5d3ca604dc5d416593c660be5ea4f313491))

- Inject CredentialBackend into PerPluginStore (default LocalFs)
  ([#488](https://github.com/n24q02m/mcp-core/pull/488),
  [`b720d5d`](https://github.com/n24q02m/mcp-core/commit/b720d5d3ca604dc5d416593c660be5ea4f313491))

- Mirror CredentialBackend + CfKvBackend in core-ts
  ([#488](https://github.com/n24q02m/mcp-core/pull/488),
  [`b720d5d`](https://github.com/n24q02m/mcp-core/commit/b720d5d3ca604dc5d416593c660be5ea4f313491))

- Pluggable credential storage backend for serverless deploys
  ([#488](https://github.com/n24q02m/mcp-core/pull/488),
  [`b720d5d`](https://github.com/n24q02m/mcp-core/commit/b720d5d3ca604dc5d416593c660be5ea4f313491))

- Select credential backend from MCP_STORAGE_BACKEND env
  ([#488](https://github.com/n24q02m/mcp-core/pull/488),
  [`b720d5d`](https://github.com/n24q02m/mcp-core/commit/b720d5d3ca604dc5d416593c660be5ea4f313491))


## v1.18.0-beta.3 (2026-06-14)

### Bug Fixes

- Apply ruff format to core-py JWT signing-seed tests
  ([#484](https://github.com/n24q02m/mcp-core/pull/484),
  [`23d6864`](https://github.com/n24q02m/mcp-core/commit/23d6864d60a8a1e07ac10b07c581dbba168471f5))

- Derive EdDSA in core-py OAuth-app factory fallback from CREDENTIAL_SECRET
  ([#484](https://github.com/n24q02m/mcp-core/pull/484),
  [`23d6864`](https://github.com/n24q02m/mcp-core/commit/23d6864d60a8a1e07ac10b07c581dbba168471f5))

- Drop secret-keyword from JWTIssuer startup log (SAST false positive)
  ([#484](https://github.com/n24q02m/mcp-core/pull/484),
  [`23d6864`](https://github.com/n24q02m/mcp-core/commit/23d6864d60a8a1e07ac10b07c581dbba168471f5))

- Pass through check_capability when litellm is unavailable
  ([#483](https://github.com/n24q02m/mcp-core/pull/483),
  [`1ae4677`](https://github.com/n24q02m/mcp-core/commit/1ae4677f90b1e0cc29dbe8a5c8be1b546fc0194a))

- Remove orphaned Qodo pr-agent config ([#439](https://github.com/n24q02m/mcp-core/pull/439),
  [`a4afbe7`](https://github.com/n24q02m/mcp-core/commit/a4afbe71986241e1deeb49342e6a80b0f8a46f9a))

- Sync cross-promo section and tagline to current descriptions
  ([#442](https://github.com/n24q02m/mcp-core/pull/442),
  [`8109f5a`](https://github.com/n24q02m/mcp-core/commit/8109f5ae146755e1b25079277f6ffad7dd034cc3))

- Sync README tagline to current capability description
  ([#441](https://github.com/n24q02m/mcp-core/pull/441),
  [`33c5241`](https://github.com/n24q02m/mcp-core/commit/33c52415cb793d8ce62a933c39d27ad2e77bbd7e))

- **deps**: Lock file maintenance ([#445](https://github.com/n24q02m/mcp-core/pull/445),
  [`3a6f515`](https://github.com/n24q02m/mcp-core/commit/3a6f51517dbbe0f11ead316ffa62096b20ffb22f))

- **deps**: Update cryptography to v49 ([#444](https://github.com/n24q02m/mcp-core/pull/444),
  [`6de412e`](https://github.com/n24q02m/mcp-core/commit/6de412e28f001bbe2c81a6d771cdb68b355d3214))

- **deps**: Update non-major dependencies ([#443](https://github.com/n24q02m/mcp-core/pull/443),
  [`78c745a`](https://github.com/n24q02m/mcp-core/commit/78c745a6288689ad41cd29094666f16ffe5894a0))

- **deps**: Update non-major dependencies ([#436](https://github.com/n24q02m/mcp-core/pull/436),
  [`ebe952d`](https://github.com/n24q02m/mcp-core/commit/ebe952dce07a7da740faa62fdedaf81305a2936c))

- **deps**: Update semgrep/semgrep Docker digest to f4791a5
  ([#434](https://github.com/n24q02m/mcp-core/pull/434),
  [`98ca225`](https://github.com/n24q02m/mcp-core/commit/98ca225a9f481545f1e396771c14b63cb90d6d6b))

- **deps**: Update step-security/harden-runner digest to 9af89fc
  ([#435](https://github.com/n24q02m/mcp-core/pull/435),
  [`330dd5d`](https://github.com/n24q02m/mcp-core/commit/330dd5df98364e77ec1d64188a978e6c57e1ff20))

### Features

- Add accessible error state to relay login form
  ([#440](https://github.com/n24q02m/mcp-core/pull/440),
  [`698abac`](https://github.com/n24q02m/mcp-core/commit/698abac3c5f136aa9a9c0ef6e0d1a705f8f94184))

- Add advisory capability check to vertex express adapter
  ([#483](https://github.com/n24q02m/mcp-core/pull/483),
  [`1ae4677`](https://github.com/n24q02m/mcp-core/commit/1ae4677f90b1e0cc29dbe8a5c8be1b546fc0194a))

- Add DNS-pinning sync SSRF-safe client to mcp_core.http
  ([#483](https://github.com/n24q02m/mcp-core/pull/483),
  [`1ae4677`](https://github.com/n24q02m/mcp-core/commit/1ae4677f90b1e0cc29dbe8a5c8be1b546fc0194a))

- Add HKDF JWT signing-seed derivation in core-py
  ([#484](https://github.com/n24q02m/mcp-core/pull/484),
  [`23d6864`](https://github.com/n24q02m/mcp-core/commit/23d6864d60a8a1e07ac10b07c581dbba168471f5))

- Add HKDF JWT signing-seed derivation in core-ts
  ([#484](https://github.com/n24q02m/mcp-core/pull/484),
  [`23d6864`](https://github.com/n24q02m/mcp-core/commit/23d6864d60a8a1e07ac10b07c581dbba168471f5))

- Add vertex express async and sync http entry points
  ([#483](https://github.com/n24q02m/mcp-core/pull/483),
  [`1ae4677`](https://github.com/n24q02m/mcp-core/commit/1ae4677f90b1e0cc29dbe8a5c8be1b546fc0194a))

- Add vertex express prefix detection and response dataclasses
  ([#483](https://github.com/n24q02m/mcp-core/pull/483),
  [`1ae4677`](https://github.com/n24q02m/mcp-core/commit/1ae4677f90b1e0cc29dbe8a5c8be1b546fc0194a))

- Bolt optimize bearer token extraction ([#437](https://github.com/n24q02m/mcp-core/pull/437),
  [`25b444d`](https://github.com/n24q02m/mcp-core/commit/25b444d889f66529e4f462c3c442b1d9240b35e3))

- Build vertex express generateContent request from openai messages
  ([#483](https://github.com/n24q02m/mcp-core/pull/483),
  [`1ae4677`](https://github.com/n24q02m/mcp-core/commit/1ae4677f90b1e0cc29dbe8a5c8be1b546fc0194a))

- Derive stable EdDSA JWT signing key from CREDENTIAL_SECRET in core-py
  ([#484](https://github.com/n24q02m/mcp-core/pull/484),
  [`23d6864`](https://github.com/n24q02m/mcp-core/commit/23d6864d60a8a1e07ac10b07c581dbba168471f5))

- Derive stable EdDSA JWT signing key from CREDENTIAL_SECRET in core-ts
  ([#484](https://github.com/n24q02m/mcp-core/pull/484),
  [`23d6864`](https://github.com/n24q02m/mcp-core/commit/23d6864d60a8a1e07ac10b07c581dbba168471f5))

- Export vertex express adapter from mcp_core.llm
  ([#483](https://github.com/n24q02m/mcp-core/pull/483),
  [`1ae4677`](https://github.com/n24q02m/mcp-core/commit/1ae4677f90b1e0cc29dbe8a5c8be1b546fc0194a))

- Harden vertex express adapter request building
  ([#483](https://github.com/n24q02m/mcp-core/pull/483),
  [`1ae4677`](https://github.com/n24q02m/mcp-core/commit/1ae4677f90b1e0cc29dbe8a5c8be1b546fc0194a))

- Improve form accessibility with aria-labelledby attribute
  ([#447](https://github.com/n24q02m/mcp-core/pull/447),
  [`20bd491`](https://github.com/n24q02m/mcp-core/commit/20bd4915445ed0f959ae0ad26af567f85576230c))

- Map vertex_express prefix to GOOGLE_VERTEX_EXPRESS_API_KEY
  ([#483](https://github.com/n24q02m/mcp-core/pull/483),
  [`1ae4677`](https://github.com/n24q02m/mcp-core/commit/1ae4677f90b1e0cc29dbe8a5c8be1b546fc0194a))

- Mount JWKS endpoint and advertise jwks_uri in core-py
  ([#484](https://github.com/n24q02m/mcp-core/pull/484),
  [`23d6864`](https://github.com/n24q02m/mcp-core/commit/23d6864d60a8a1e07ac10b07c581dbba168471f5))

- Mount JWKS endpoint and advertise jwks_uri in core-ts
  ([#484](https://github.com/n24q02m/mcp-core/pull/484),
  [`23d6864`](https://github.com/n24q02m/mcp-core/commit/23d6864d60a8a1e07ac10b07c581dbba168471f5))

- Route vertex_express prefix to direct generateContent adapter
  ([#483](https://github.com/n24q02m/mcp-core/pull/483),
  [`1ae4677`](https://github.com/n24q02m/mcp-core/commit/1ae4677f90b1e0cc29dbe8a5c8be1b546fc0194a))

- Select EdDSA issuer mode from CREDENTIAL_SECRET in build_local_app
  ([#484](https://github.com/n24q02m/mcp-core/pull/484),
  [`23d6864`](https://github.com/n24q02m/mcp-core/commit/23d6864d60a8a1e07ac10b07c581dbba168471f5))

- Select EdDSA issuer mode from CREDENTIAL_SECRET in core-ts OAuth apps
  ([#484](https://github.com/n24q02m/mcp-core/pull/484),
  [`23d6864`](https://github.com/n24q02m/mcp-core/commit/23d6864d60a8a1e07ac10b07c581dbba168471f5))

- Stable OAuth JWT signing key derived from CREDENTIAL_SECRET
  ([#484](https://github.com/n24q02m/mcp-core/pull/484),
  [`23d6864`](https://github.com/n24q02m/mcp-core/commit/23d6864d60a8a1e07ac10b07c581dbba168471f5))

- Translate vertex express generateContent response to chatcompletion shape
  ([#483](https://github.com/n24q02m/mcp-core/pull/483),
  [`1ae4677`](https://github.com/n24q02m/mcp-core/commit/1ae4677f90b1e0cc29dbe8a5c8be1b546fc0194a))

- Vertex AI Express generateContent passthrough adapter
  ([#483](https://github.com/n24q02m/mcp-core/pull/483),
  [`1ae4677`](https://github.com/n24q02m/mcp-core/commit/1ae4677f90b1e0cc29dbe8a5c8be1b546fc0194a))


## v1.18.0-beta.2 (2026-06-11)

### Features

- Canonical model-prefix to credential-env map (mcp_core.llm.providers)
  ([#438](https://github.com/n24q02m/mcp-core/pull/438),
  [`7ff3c9e`](https://github.com/n24q02m/mcp-core/commit/7ff3c9ec98995d1bd909a12636d644eb806fe302))

- Model-chain + derived keys in ConfigField schema
  ([#438](https://github.com/n24q02m/mcp-core/pull/438),
  [`7ff3c9e`](https://github.com/n24q02m/mcp-core/commit/7ff3c9ec98995d1bd909a12636d644eb806fe302))

- Model-chain widget JS (chip dropdown-checkbox + drag-reorder + derive-keys)
  ([#438](https://github.com/n24q02m/mcp-core/pull/438),
  [`7ff3c9e`](https://github.com/n24q02m/mcp-core/commit/7ff3c9ec98995d1bd909a12636d644eb806fe302))

- Relay model-chain widget + provider->key map (selection redesign Phase 1)
  ([#438](https://github.com/n24q02m/mcp-core/pull/438),
  [`7ff3c9e`](https://github.com/n24q02m/mcp-core/commit/7ff3c9ec98995d1bd909a12636d644eb806fe302))

- Render model-chain widget + derived credential fields in relay form
  ([#438](https://github.com/n24q02m/mcp-core/pull/438),
  [`7ff3c9e`](https://github.com/n24q02m/mcp-core/commit/7ff3c9ec98995d1bd909a12636d644eb806fe302))


## v1.18.0-beta.1 (2026-06-10)

### Bug Fixes

- Harden mcp_core.http SSRF guard (unspecified-address block + single-hop async DNS)
  ([#433](https://github.com/n24q02m/mcp-core/pull/433),
  [`fb8aee8`](https://github.com/n24q02m/mcp-core/commit/fb8aee8f5ea668b865e965e42a3e9cab3cf6b015))

- Harden mcp_core.llm.catalog (mode-less registry entries + empty-hints message)
  ([#433](https://github.com/n24q02m/mcp-core/pull/433),
  [`fb8aee8`](https://github.com/n24q02m/mcp-core/commit/fb8aee8f5ea668b865e965e42a3e9cab3cf6b015))

- Omit None credentials from litellm kwargs (env-fallback suppression) + sync wrapper warnings
  ([#433](https://github.com/n24q02m/mcp-core/pull/433),
  [`fb8aee8`](https://github.com/n24q02m/mcp-core/commit/fb8aee8f5ea668b865e965e42a3e9cab3cf6b015))

### Features

- Add mcp_core.http SSRF guard (DNS-pinned transport + api_base policy)
  ([#433](https://github.com/n24q02m/mcp-core/pull/433),
  [`fb8aee8`](https://github.com/n24q02m/mcp-core/commit/fb8aee8f5ea668b865e965e42a3e9cab3cf6b015))

- Add mcp_core.llm dispatch passthrough wrappers (async + sync mirrors)
  ([#433](https://github.com/n24q02m/mcp-core/pull/433),
  [`fb8aee8`](https://github.com/n24q02m/mcp-core/commit/fb8aee8f5ea668b865e965e42a3e9cab3cf6b015))

- Add mcp_core.llm.catalog (capability check + model listing, graceful-on-missing)
  ([#433](https://github.com/n24q02m/mcp-core/pull/433),
  [`fb8aee8`](https://github.com/n24q02m/mcp-core/commit/fb8aee8f5ea668b865e965e42a3e9cab3cf6b015))

- Mcp_core.llm passthrough primitive + mcp_core.http SSRF guard
  ([#433](https://github.com/n24q02m/mcp-core/pull/433),
  [`fb8aee8`](https://github.com/n24q02m/mcp-core/commit/fb8aee8f5ea668b865e965e42a3e9cab3cf6b015))

- Wire mcp-core[llm] optional extra + CI extras legs
  ([#433](https://github.com/n24q02m/mcp-core/pull/433),
  [`fb8aee8`](https://github.com/n24q02m/mcp-core/commit/fb8aee8f5ea668b865e965e42a3e9cab3cf6b015))


## v1.17.5-beta.3 (2026-06-10)

### Bug Fixes

- Add path traversal protection to PerPluginStore
  ([#429](https://github.com/n24q02m/mcp-core/pull/429),
  [`8a58836`](https://github.com/n24q02m/mcp-core/commit/8a58836cbe52d1ad67f0fc8161a265add1911dfc))

- Sanitize cache filenames to prevent path traversal
  ([#427](https://github.com/n24q02m/mcp-core/pull/427),
  [`1773e8a`](https://github.com/n24q02m/mcp-core/commit/1773e8a5aff9086584296548a937daa39446e750))

- Secure JWT private keys by disabling memory extraction
  ([#428](https://github.com/n24q02m/mcp-core/pull/428),
  [`caddcfd`](https://github.com/n24q02m/mcp-core/commit/caddcfd60715615c54203ef51e76dc8df822b5e3))


## v1.17.5-beta.2 (2026-06-10)

### Bug Fixes

- Align mcp-core docs/config with library reality
  ([#401](https://github.com/n24q02m/mcp-core/pull/401),
  [`e9788a7`](https://github.com/n24q02m/mcp-core/commit/e9788a7555fa4b98ef81b16d50c975a87179f2d7))


## v1.17.5-beta.1 (2026-06-10)

### Bug Fixes

- Ruff-format e2e oauth client hardening test (downstream vendor CI)
  ([`293db81`](https://github.com/n24q02m/mcp-core/commit/293db81328555c733a94ce85751709c9fc73c8fa))


## v1.17.4 (2026-06-09)


## v1.17.4-beta.1 (2026-06-09)

### Bug Fixes

- Fix silent failure mode driver bug in OAuth flows
  ([#372](https://github.com/n24q02m/mcp-core/pull/372),
  [`62a4950`](https://github.com/n24q02m/mcp-core/commit/62a4950a5b69922c0762dd2b9261c9b94b9441b3))

- Gitignore bot/merge junk artifacts (*.orig/*.rej/*.patch/*.diff/*.cover/*.bak)
  ([#353](https://github.com/n24q02m/mcp-core/pull/353),
  [`f69f556`](https://github.com/n24q02m/mcp-core/commit/f69f556c5cd85ac458378654962c253732829f96))

- **deps**: Lock file maintenance ([#356](https://github.com/n24q02m/mcp-core/pull/356),
  [`b121d1d`](https://github.com/n24q02m/mcp-core/commit/b121d1d770c3582a1897bc0c857030e642c753e3))

- **deps**: Update codecov/codecov-action action to v7
  ([#355](https://github.com/n24q02m/mcp-core/pull/355),
  [`4c4b0fc`](https://github.com/n24q02m/mcp-core/commit/4c4b0fc440fe53f65ceb56802bc59db621e61fec))

- **deps**: Update non-major dependencies ([#397](https://github.com/n24q02m/mcp-core/pull/397),
  [`b17ccb1`](https://github.com/n24q02m/mcp-core/commit/b17ccb1a69dae8a09e33148f646dc5506b569c1f))


## v1.17.3 (2026-06-07)


## v1.17.3-beta.2 (2026-06-07)

### Bug Fixes

- Create JWT keys dir with mode 0o700 to close TOCTOU window
  ([#352](https://github.com/n24q02m/mcp-core/pull/352),
  [`c225ddc`](https://github.com/n24q02m/mcp-core/commit/c225ddcbd70b8a12501c9e361fc309ad97836c74))


## v1.17.3-beta.1 (2026-06-07)

### Bug Fixes

- Add exception-handling tests for Python OAuth apps
  ([`0750d08`](https://github.com/n24q02m/mcp-core/commit/0750d085310b2cd01b7ac3bdf52497ed453d3905))

- Add tests for clean_state script
  ([`ffd15f2`](https://github.com/n24q02m/mcp-core/commit/ffd15f2e16780bce8b2fdc044611c932d0685c56))

- Add tests for Python OAuthProvider
  ([`59f0517`](https://github.com/n24q02m/mcp-core/commit/59f0517d0d633e037878c4b51330047a70be0537))

- Add tests for Python relay session token
  ([`87e8a59`](https://github.com/n24q02m/mcp-core/commit/87e8a5955c9171240a54045ca9c6cd169d7f8454))

- Add tests for Python relay tool_helpers
  ([`e0f116f`](https://github.com/n24q02m/mcp-core/commit/e0f116f75ae779c6a970616c20e8bc466d4f2be8))

- Add tests for TypeScript PKCE utilities
  ([`30dd048`](https://github.com/n24q02m/mcp-core/commit/30dd048b6e256ec23315dccf7e1ae4f241821da4))

- Add tests for TypeScript transport cache version key
  ([`1a6bc36`](https://github.com/n24q02m/mcp-core/commit/1a6bc36f26c4ce3206d85223fecdef087727fef5))

- Remove aria-hidden from optional field badges for screen readers
  ([`9eea86e`](https://github.com/n24q02m/mcp-core/commit/9eea86e8c30a0dae6a6204e35b9c7e5a9336d51a))

- Update actions/checkout digest to df4cb1c
  ([`899db3d`](https://github.com/n24q02m/mcp-core/commit/899db3dfbb6c3b6ecbf09543b9438f3d74731214))

- Update non-major dependencies
  ([`6463ff2`](https://github.com/n24q02m/mcp-core/commit/6463ff2a82d22b7161ed2ced51053305df02f8ad))

- Update semgrep/semgrep Docker digest to 2079836
  ([`55a67a8`](https://github.com/n24q02m/mcp-core/commit/55a67a8f593bcd9e8fe1878f2e2fb628230b1929))


## v1.17.2 (2026-06-01)


## v1.17.2-beta.1 (2026-06-01)

### Bug Fixes

- Correct mcp-core Dockerfile header ([#302](https://github.com/n24q02m/mcp-core/pull/302),
  [`954af42`](https://github.com/n24q02m/mcp-core/commit/954af42865c681a39806ab7add7bb4b380fa310b))

- Sync mcp-core docs with current code ([#301](https://github.com/n24q02m/mcp-core/pull/301),
  [`adea6aa`](https://github.com/n24q02m/mcp-core/commit/adea6aa8c7d43fb82b744cee7e1d94d452eaea63))

- Update non-major dependencies (starlette/platformdirs/ruff)
  ([`65d3181`](https://github.com/n24q02m/mcp-core/commit/65d318102453d17fa5028e8bb8c20207bad6dc55))


## v1.17.1 (2026-05-29)

### Bug Fixes

- Apply ruff format to BearerMCPApp resource_metadata tests
  ([#295](https://github.com/n24q02m/mcp-core/pull/295),
  [`f7af00e`](https://github.com/n24q02m/mcp-core/commit/f7af00e82d970150cd9d56a853e1715f05991b4b))

- Emit RFC9728 resource_metadata in BearerMCPApp 401 challenge
  ([#295](https://github.com/n24q02m/mcp-core/pull/295),
  [`f7af00e`](https://github.com/n24q02m/mcp-core/commit/f7af00e82d970150cd9d56a853e1715f05991b4b))

- Emit RFC9728 resource_metadata in BearerMCPApp 401 challenge (#260)
  ([#295](https://github.com/n24q02m/mcp-core/pull/295),
  [`f7af00e`](https://github.com/n24q02m/mcp-core/commit/f7af00e82d970150cd9d56a853e1715f05991b4b))


## v1.17.0 (2026-05-29)


## v1.17.0-beta.1 (2026-05-29)

### Bug Fixes

- Avoid env-var URL passing in WSL PowerShell browser open
  ([#288](https://github.com/n24q02m/mcp-core/pull/288),
  [`45274ae`](https://github.com/n24q02m/mcp-core/commit/45274ae47d83d2726eceb1bdd7e9ffaf6d4c98e0))

- Await Future-returning OAuth callbacks via isawaitable
  ([#283](https://github.com/n24q02m/mcp-core/pull/283),
  [`8c1bd4c`](https://github.com/n24q02m/mcp-core/commit/8c1bd4c50328582a59ecb42489be7a753abf1467))

- Harden open-redirect validation in relay login
  ([#293](https://github.com/n24q02m/mcp-core/pull/293),
  [`282dcb6`](https://github.com/n24q02m/mcp-core/commit/282dcb673f4be52d11ba5555f2082ae95c376818))

- Refactor OAuthProvider into cache/pkce modules
  ([#277](https://github.com/n24q02m/mcp-core/pull/277),
  [`3c4e32c`](https://github.com/n24q02m/mcp-core/commit/3c4e32c458602ddb19193208b0872913a4499d64))

- Secure browser opening via PowerShell in WSL/win32
  ([#288](https://github.com/n24q02m/mcp-core/pull/288),
  [`45274ae`](https://github.com/n24q02m/mcp-core/commit/45274ae47d83d2726eceb1bdd7e9ffaf6d4c98e0))

- Use per-file random salt for config encryption
  ([#291](https://github.com/n24q02m/mcp-core/pull/291),
  [`8cb514d`](https://github.com/n24q02m/mcp-core/commit/8cb514d4d8b265a2b4a98a8e4566857aeba599ff))

### Features

- Add OAuth refresh_token grant and offline_access scope (#261)
  ([#294](https://github.com/n24q02m/mcp-core/pull/294),
  [`f685feb`](https://github.com/n24q02m/mcp-core/commit/f685feb4ab7d60281bc4136cd73678589f9ec5d2))


## v1.16.0 (2026-05-28)


## v1.16.0-beta.1 (2026-05-28)

### Bug Fixes

- **auth**: Prevent open redirect bypass via backslashes in relay login
  ([#259](https://github.com/n24q02m/mcp-core/pull/259),
  [`9db71bf`](https://github.com/n24q02m/mcp-core/commit/9db71bfe3da739aff22f0eafda1c3913b9b01db3))

- **core-py**: Relax pydantic to >=2.12.5,<3 for downstream pydantic 2.13 compat
  ([`49130c8`](https://github.com/n24q02m/mcp-core/commit/49130c8f82c1dddba92d27d594f1e5e77a034eea))

- **deps**: Update non-major dependencies ([#256](https://github.com/n24q02m/mcp-core/pull/256),
  [`9c3f9b3`](https://github.com/n24q02m/mcp-core/commit/9c3f9b3a0ac0bd5b9bdf7f06876524f0e91ecc2d))

### Features

- Refactor dynamic step prompt to use explicit label linking
  ([#258](https://github.com/n24q02m/mcp-core/pull/258),
  [`6556e68`](https://github.com/n24q02m/mcp-core/commit/6556e687a16ddf84f611bc9f24579e24b5f42e2d))


## v1.15.0 (2026-05-26)


## v1.15.0-beta.3 (2026-05-26)

### Bug Fixes

- **deps**: Lock file maintenance ([#254](https://github.com/n24q02m/mcp-core/pull/254),
  [`e3d3fa5`](https://github.com/n24q02m/mcp-core/commit/e3d3fa5362cb35acdf320b20685b89ab347602bd))

### Features

- Explicitly link label and input elements in transient form
  ([#255](https://github.com/n24q02m/mcp-core/pull/255),
  [`4948701`](https://github.com/n24q02m/mcp-core/commit/494870122d6d4ebdfeb1cecd2322b7a5cf442527))

- **transport**: Add auth_disabled to BearerMCPApp + run_http_server (Python parity)
  ([`ae893e2`](https://github.com/n24q02m/mcp-core/commit/ae893e222cb121e3a670aff15b2e5625bb15965e))


## v1.15.0-beta.2 (2026-05-25)

### Bug Fixes

- **a11y**: Explicitly link labels to inputs in local oauth app
  ([#253](https://github.com/n24q02m/mcp-core/pull/253),
  [`252f0db`](https://github.com/n24q02m/mcp-core/commit/252f0db138f0bf1a4d59408bc282e8acc5b2e67b))

- **deps**: Lock file maintenance ([#252](https://github.com/n24q02m/mcp-core/pull/252),
  [`c7d9e30`](https://github.com/n24q02m/mcp-core/commit/c7d9e30edeca3aa16514aa74504d3b0289000510))

- **deps**: Update uvicorn to >=0.48.0 ([#251](https://github.com/n24q02m/mcp-core/pull/251),
  [`13b70c3`](https://github.com/n24q02m/mcp-core/commit/13b70c3f21d704ed099006a962c8fb607e6dade8))

### Features

- **transport**: Add authDisabled flag to OAuthMiddleware for external auth boundary
  ([`d303aa0`](https://github.com/n24q02m/mcp-core/commit/d303aa07166570266a7a01c270e18512d02a3cda))

- **transport**: Plumb authDisabled through runHttpServer for inline auth bypass
  ([`15163a5`](https://github.com/n24q02m/mcp-core/commit/15163a5d440a1b57daa95ea1cb9dee8b942c7433))


## v1.15.0-beta.1 (2026-05-24)

### Bug Fixes

- Add missing error path test for cache persistence OSError
  ([#172](https://github.com/n24q02m/mcp-core/pull/172),
  [`37b8016`](https://github.com/n24q02m/mcp-core/commit/37b80167acb43d5b2fc6a99f974a08d3d9221029))

- Bump crg-stdio-direct pin to 3.15.0b1 for v1.6 E2E matrix
  ([`4692eb6`](https://github.com/n24q02m/mcp-core/commit/4692eb6715ef5539d0fd5a27cb45f96e7e168ce3))

- Bump crg-stdio-direct pin to 3.15.1b2 for current beta cycle
  ([`5367c87`](https://github.com/n24q02m/mcp-core/commit/5367c87f7c7f4efe42fa2a166e678b3cba2120ac))

- Bump vitest timeout to 60s for slow CI Windows runner
  ([`ad2ea8b`](https://github.com/n24q02m/mcp-core/commit/ad2ea8b7fff5ce5f33ee99fd9e019f45e9d35625))

- Centralize _base_url derivation in well_known.derive_base_url
  ([`b8c2606`](https://github.com/n24q02m/mcp-core/commit/b8c2606ea0fa9a131e06f9e305b2317fe49394a3))

- Drop --body-file flag (older gh CLI on runner)
  ([`7a075d8`](https://github.com/n24q02m/mcp-core/commit/7a075d84f039fbc8672a038c9a6a0667b01f6b8c))

- Harden core-ts crypto + suppress semgrep FPs + bump test timeout
  ([`c460581`](https://github.com/n24q02m/mcp-core/commit/c460581db73785c409113c108a9e11d510aa4b3e))

- Inject skret env into stdio-direct configs (v2)
  ([`48d27e4`](https://github.com/n24q02m/mcp-core/commit/48d27e45ce36186b240f22012a18e545a864d3ef))

- Pin e2e matrix stdio-direct to imagine 1.4.0b1 + telegram 4.11.0b2 betas
  ([`7079702`](https://github.com/n24q02m/mcp-core/commit/7079702358c79f5aba504eaf4753c2ba30535188))

- Reject $, (, ) in try_open_browser URL validation
  ([`e316983`](https://github.com/n24q02m/mcp-core/commit/e3169831a84575f3c2138cf2cd96f4c7c1e848ac))

- Remove one-shot CI_APP_KEY propagation workflow (job done)
  ([`8d0f162`](https://github.com/n24q02m/mcp-core/commit/8d0f162bee7487ce2a01fbbdb0279821f96cf362))

- Rephrase BUG label to invariant violation in driver.py comment
  ([`bc647cf`](https://github.com/n24q02m/mcp-core/commit/bc647cf3cbbe8de4177f07bb83f79f6d64d9f430))

- Rephrase running-loop-hacks comment to clearer wording
  ([`71bd4b1`](https://github.com/n24q02m/mcp-core/commit/71bd4b168bc8212f8e54c48717477d189b14d3ee))

- Replace filter+map+every with single-pass loop in isSchemaComplete
  ([`6b57679`](https://github.com/n24q02m/mcp-core/commit/6b576794d45394a3c875cb0636f0b77388076060))

- Replace sync fs.unlinkSync with async fs.promises.unlink on HTTP shutdown
  ([`a883715`](https://github.com/n24q02m/mcp-core/commit/a8837154ef88d8b6f08ee1dc1c4b70391eaeb667))

- Resolve timing attack vulnerabilities in timingSafeEqual
  ([#223](https://github.com/n24q02m/mcp-core/pull/223),
  [`3738a06`](https://github.com/n24q02m/mcp-core/commit/3738a0694bcae6931713111b660411331c1f0f03))

- Resolve tryOpenBrowser timeout in local-server.test.ts
  ([#223](https://github.com/n24q02m/mcp-core/pull/223),
  [`3738a06`](https://github.com/n24q02m/mcp-core/commit/3738a0694bcae6931713111b660411331c1f0f03))

- Secure PowerShell browser open via env var instead of command concat
  ([`b1fdabc`](https://github.com/n24q02m/mcp-core/commit/b1fdabc26e49e548306acad10a650cf33d559009))

- Test agents atomic write error path ([#175](https://github.com/n24q02m/mcp-core/pull/175),
  [`ce187cf`](https://github.com/n24q02m/mcp-core/commit/ce187cf5f0b6eaa6aac2e4150e01e8371b10505a))

- Use prepared statement instead of db.exec in SqliteUserStore
  ([`a71e692`](https://github.com/n24q02m/mcp-core/commit/a71e692ad3750c910c1b7c630f1e5bb7fb92f79d))

- **a11y**: Hide redundant Required/Optional badges from screen readers
  ([#241](https://github.com/n24q02m/mcp-core/pull/241),
  [`c1dbdd4`](https://github.com/n24q02m/mcp-core/commit/c1dbdd40663c84220e2df37929a857c2fa6b7245))

- **core-ts**: Add missing authTagLength to createCipheriv call
  ([#250](https://github.com/n24q02m/mcp-core/pull/250),
  [`5a39fb2`](https://github.com/n24q02m/mcp-core/commit/5a39fb2611c5f71614e375d72115069e788b0733))

- **deps**: Bump idna and urllib3 in the uv group across 3 directories
  ([#236](https://github.com/n24q02m/mcp-core/pull/236),
  [`bb9f234`](https://github.com/n24q02m/mcp-core/commit/bb9f2340c27ab305c4fcd9ad174d3cb67456a3e9))

- **deps**: Lock file maintenance ([#248](https://github.com/n24q02m/mcp-core/pull/248),
  [`cbe278e`](https://github.com/n24q02m/mcp-core/commit/cbe278e4cedb2e3782a801e006af48a779adcd22))

- **deps**: Lock file maintenance ([#201](https://github.com/n24q02m/mcp-core/pull/201),
  [`9146183`](https://github.com/n24q02m/mcp-core/commit/914618357b129f6e680e98a6af9da36c4dafb329))

- **deps**: Re-run CI for lock file maintenance
  ([#248](https://github.com/n24q02m/mcp-core/pull/248),
  [`cbe278e`](https://github.com/n24q02m/mcp-core/commit/cbe278e4cedb2e3782a801e006af48a779adcd22))

- **deps**: Re-run CI for lock file maintenance
  ([#201](https://github.com/n24q02m/mcp-core/pull/201),
  [`9146183`](https://github.com/n24q02m/mcp-core/commit/914618357b129f6e680e98a6af9da36c4dafb329))

- **deps**: Refresh lock file maintenance ([#201](https://github.com/n24q02m/mcp-core/pull/201),
  [`9146183`](https://github.com/n24q02m/mcp-core/commit/914618357b129f6e680e98a6af9da36c4dafb329))

- **deps**: Update actions/create-github-app-token digest to bcd2ba4
  ([#217](https://github.com/n24q02m/mcp-core/pull/217),
  [`27ddf2f`](https://github.com/n24q02m/mcp-core/commit/27ddf2f9f1cbb74ec2ebe5aab8172da7d48fb7a7))

- **deps**: Update actions/dependency-review-action action to v5
  ([#202](https://github.com/n24q02m/mcp-core/pull/202),
  [`40fbc54`](https://github.com/n24q02m/mcp-core/commit/40fbc5497929f8650c600ee277c7db84b7ac9c5d))

- **deps**: Update codecov/codecov-action digest to e79a696
  ([#243](https://github.com/n24q02m/mcp-core/pull/243),
  [`f32b5d8`](https://github.com/n24q02m/mcp-core/commit/f32b5d82ad54012a44251707f6f238019418285e))

- **deps**: Update non-major dependencies ([#247](https://github.com/n24q02m/mcp-core/pull/247),
  [`c155dc3`](https://github.com/n24q02m/mcp-core/commit/c155dc3302d06a8d91d9e7d9d6b872e24fe8355f))

- **deps**: Update non-major dependencies ([#200](https://github.com/n24q02m/mcp-core/pull/200),
  [`ff2ba1b`](https://github.com/n24q02m/mcp-core/commit/ff2ba1b3a8aecae130f59aefa41339d8d072f8f9))

- **deps**: Update non-major dependencies ([#167](https://github.com/n24q02m/mcp-core/pull/167),
  [`3d1e76b`](https://github.com/n24q02m/mcp-core/commit/3d1e76b58042a0f8f7fae6cee0b3d17efb2f695d))

- **deps**: Update oven/bun:1-alpine Docker digest to 5acc90a
  ([#218](https://github.com/n24q02m/mcp-core/pull/218),
  [`3078766`](https://github.com/n24q02m/mcp-core/commit/307876683cfba97a1e3f8d7df41ee9e68958993d))

- **deps**: Update semgrep/semgrep Docker digest to 7cad2bc
  ([#244](https://github.com/n24q02m/mcp-core/pull/244),
  [`9c2c47c`](https://github.com/n24q02m/mcp-core/commit/9c2c47c8d4ca9bb64631c07eccc43099394fef13))

- **deps**: Update step-security/harden-runner digest to ab7a940
  ([#245](https://github.com/n24q02m/mcp-core/pull/245),
  [`52983b4`](https://github.com/n24q02m/mcp-core/commit/52983b414835a7497f55f645d058d8508b40d4d5))

- **e2e**: Add public DNS to email compose + error-type announce
  ([`5a109f9`](https://github.com/n24q02m/mcp-core/commit/5a109f9060929510fd69cef474171465488ea666))

- **e2e**: Drop T2 driver matrix entries (replaced by Test B matrix-in-settings)
  ([#205](https://github.com/n24q02m/mcp-core/pull/205),
  [`e782818`](https://github.com/n24q02m/mcp-core/commit/e78281897b55e5e3aef63d0948813974b71ad23e))

- **e2e**: Force docker pull always + ipv4-first DNS for outlook
  ([`4a0d32c`](https://github.com/n24q02m/mcp-core/commit/4a0d32cbbe7b6443973268702d61cf72d2dc45ca))

- **e2e**: Inject CREDENTIAL_SECRET env for multi-user mode
  ([`9875953`](https://github.com/n24q02m/mcp-core/commit/9875953a0ceaab7b1f09a447e07a3f8df47dde1d))

- **e2e**: Inject skret env into stdio-direct configs and tighten browser URL validation
  ([`de39607`](https://github.com/n24q02m/mcp-core/commit/de3960770e3dfda25a736b81bf2e8eec1e679f5e))

- **security**: Fix timing leak in constant-time comparison
  ([#223](https://github.com/n24q02m/mcp-core/pull/223),
  [`3738a06`](https://github.com/n24q02m/mcp-core/commit/3738a0694bcae6931713111b660411331c1f0f03))

- **security**: Use safe urljoin to prevent SSRF in relay client
  ([#219](https://github.com/n24q02m/mcp-core/pull/219),
  [`4924ebf`](https://github.com/n24q02m/mcp-core/commit/4924ebfa4cd2da92b333f3e2c18af18e1d157090))

- **security**: Validate next redirect param in relay login
  ([#242](https://github.com/n24q02m/mcp-core/pull/242),
  [`cf80c27`](https://github.com/n24q02m/mcp-core/commit/cf80c270989cb97488951320f39a86e4bd9a59fb))

### Chores

- **deps**: Lock file maintenance ([#168](https://github.com/n24q02m/mcp-core/pull/168),
  [`461fc74`](https://github.com/n24q02m/mcp-core/commit/461fc7411d6222314f33842bf96ece8b7ef907e3))

### Features

- Add comprehensive tests for isOAuthField and isSecretField
  ([#170](https://github.com/n24q02m/mcp-core/pull/170),
  [`1a5f480`](https://github.com/n24q02m/mcp-core/commit/1a5f4809ce869765430d59a706cc16b2f52772c4))

- Add Table of contents heading + auto-generated link list (Spec E Wave 2)
  ([`f3121d2`](https://github.com/n24q02m/mcp-core/commit/f3121d2dc7e8826e6da7a60309be965ff69192aa))

- Add test coverage for registerOpenRelayTool HTTP mode
  ([#176](https://github.com/n24q02m/mcp-core/pull/176),
  [`8e11258`](https://github.com/n24q02m/mcp-core/commit/8e11258b41d2322a65cf77468770275c6e46d130))

- Migrate docs/ content to mcp.n24q02m.com unified site (Spec F Phase 4)
  ([`f96a267`](https://github.com/n24q02m/mcp-core/commit/f96a267c3e95a880e9a0eebe0608ac8ce68f41db))

- One-shot propagate CI_APP_KEY to n24q02m/skret
  ([`f8723cb`](https://github.com/n24q02m/mcp-core/commit/f8723cbcfa61de6a46d488677770b6e3cc84bc52))

- Replace intermediate string collapse allocations with regex
  ([#249](https://github.com/n24q02m/mcp-core/pull/249),
  [`3c1983b`](https://github.com/n24q02m/mcp-core/commit/3c1983bc22d70c5c53e8598d448db773d202f9b4))

- Retrofit Tier 1 governance files via repo-bootstrap apply (Spec E Wave 4)
  ([`363efbf`](https://github.com/n24q02m/mcp-core/commit/363efbfd62b67afcd8624681c54ad202afc9cce8))

- Sync cross-promo section ([#190](https://github.com/n24q02m/mcp-core/pull/190),
  [`8d3adb7`](https://github.com/n24q02m/mcp-core/commit/8d3adb75c6d9ac6338b3feed57ded7200ccf1159))

### Testing

- Add coverage for uvicorn import error and backends
  ([#173](https://github.com/n24q02m/mcp-core/pull/173),
  [`6932ea2`](https://github.com/n24q02m/mcp-core/commit/6932ea24cf8ba4e9935f3a6b65e6b36ee5abca3e))


## v1.14.0 (2026-05-06)


## v1.14.0-beta.1 (2026-05-06)

### Bug Fixes

- **deps**: Update dependency cryptography to v48
  ([#165](https://github.com/n24q02m/mcp-core/pull/165),
  [`b536172`](https://github.com/n24q02m/mcp-core/commit/b536172700ee49b51a0e78a9139e7d97532d2307))

- **deps**: Update non-major dependencies ([#155](https://github.com/n24q02m/mcp-core/pull/155),
  [`5147a19`](https://github.com/n24q02m/mcp-core/commit/5147a192836e10f1af7191bf308b7d0b70c2e7a3))

### Chores

- **deps**: Update semgrep/semgrep docker digest to 326e5f4
  ([#164](https://github.com/n24q02m/mcp-core/pull/164),
  [`80643db`](https://github.com/n24q02m/mcp-core/commit/80643db81ff0571e0b2727c8bc589bc3244856e0))

- **deps**: Update step-security/harden-runner digest to a5ad31d
  ([#154](https://github.com/n24q02m/mcp-core/pull/154),
  [`95afe41`](https://github.com/n24q02m/mcp-core/commit/95afe4103f78a1981012ed5b80c739513091dc28))

### Features

- Explicitly manage aria-errormessage for multi-step form validation
  ([#166](https://github.com/n24q02m/mcp-core/pull/166),
  [`1df79ea`](https://github.com/n24q02m/mcp-core/commit/1df79ea9966440bbb827b207a6ff60ef6bc9e82d))

### Performance Improvements

- Fix test_only_uses_words_from_wordlist flakiness
  ([#162](https://github.com/n24q02m/mcp-core/pull/162),
  [`5ce5edc`](https://github.com/n24q02m/mcp-core/commit/5ce5edce6deeff2a8e3b6beffd224f73e88a83e6))

- Replace .flat().find() with manual for loop ([#162](https://github.com/n24q02m/mcp-core/pull/162),
  [`5ce5edc`](https://github.com/n24q02m/mcp-core/commit/5ce5edce6deeff2a8e3b6beffd224f73e88a83e6))


## v1.13.0 (2026-05-04)


## v1.13.0-beta.9 (2026-05-03)

### Features

- Reuse relay form CSS for /login gate (visual parity)
  ([#160](https://github.com/n24q02m/mcp-core/pull/160),
  [`17f8e89`](https://github.com/n24q02m/mcp-core/commit/17f8e89ed59f785fb2e369d07a2a18b46238caef))


## v1.13.0-beta.8 (2026-05-03)

### Features

- Wire /login gate into delegated_oauth_app (notion delegated path)
  ([#159](https://github.com/n24q02m/mcp-core/pull/159),
  [`63c512d`](https://github.com/n24q02m/mcp-core/commit/63c512d1e28167e602e931fe62020edf6ccfec04))


## v1.13.0-beta.7 (2026-05-03)

### Bug Fixes

- Collapse relay-login form HTML to single line for Semgrep nosemgrep
  ([#158](https://github.com/n24q02m/mcp-core/pull/158),
  [`a47cdcd`](https://github.com/n24q02m/mcp-core/commit/a47cdcd65c6520344f09d7ba72b4e5a6302ae0a4))

- Place nosemgrep comment on same line as flagged HTML literal
  ([#158](https://github.com/n24q02m/mcp-core/pull/158),
  [`a47cdcd`](https://github.com/n24q02m/mcp-core/commit/a47cdcd65c6520344f09d7ba72b4e5a6302ae0a4))

- Relay-login type annotation + Semgrep XSS suppression
  ([#158](https://github.com/n24q02m/mcp-core/pull/158),
  [`a47cdcd`](https://github.com/n24q02m/mcp-core/commit/a47cdcd65c6520344f09d7ba72b4e5a6302ae0a4))

### Features

- Add MCP_RELAY_PASSWORD edge auth gate per spec §4.2.1
  ([#158](https://github.com/n24q02m/mcp-core/pull/158),
  [`a47cdcd`](https://github.com/n24q02m/mcp-core/commit/a47cdcd65c6520344f09d7ba72b4e5a6302ae0a4))

- Relay password gate (edge auth) ([#158](https://github.com/n24q02m/mcp-core/pull/158),
  [`a47cdcd`](https://github.com/n24q02m/mcp-core/commit/a47cdcd65c6520344f09d7ba72b4e5a6302ae0a4))


## v1.13.0-beta.6 (2026-05-02)

### Bug Fixes

- E2e driver — npx for TS plugins, negative test per-plugin, multi-session http <=1
  ([#151](https://github.com/n24q02m/mcp-core/pull/151),
  [`71599ec`](https://github.com/n24q02m/mcp-core/commit/71599ecb8273a5c95c2eb02d871bccd222d6a6c3))

- E2e relay_filler follow_redirects + remove obsolete notion-paste-token
  ([#152](https://github.com/n24q02m/mcp-core/pull/152),
  [`ee33d2a`](https://github.com/n24q02m/mcp-core/commit/ee33d2a64892a3f466fe0e2df18d6987d7fc53be))

- E2e strict-no-fallback negative test simulates Test B
  ([#153](https://github.com/n24q02m/mcp-core/pull/153),
  [`cea57a9`](https://github.com/n24q02m/mcp-core/commit/cea57a9d38e60f2d695fa946777792ca8167cd63))


## v1.13.0-beta.5 (2026-05-02)

### Features

- E2e matrix stdio configs + driver multi-session invariant
  ([#150](https://github.com/n24q02m/mcp-core/pull/150),
  [`14f507d`](https://github.com/n24q02m/mcp-core/commit/14f507d3d7a4aca93a5b4969cd004154f606f253))


## v1.13.0-beta.4 (2026-05-02)

### Features

- Stdio-pure + http-multi-user foundation ([#149](https://github.com/n24q02m/mcp-core/pull/149),
  [`6d0e62a`](https://github.com/n24q02m/mcp-core/commit/6d0e62a040cc4bca73605219d2a668131b9a8ebb))


## v1.13.0-beta.3 (2026-05-01)

### Bug Fixes

- **e2e**: Add --prerelease=allow to stdio-direct uvx commands
  ([#147](https://github.com/n24q02m/mcp-core/pull/147),
  [`e928a45`](https://github.com/n24q02m/mcp-core/commit/e928a459e659c0faeb796dcf451c7d2c5ea0c48a))

- **e2e**: Add --prerelease=allow to stdio-direct uvx commands
  ([#146](https://github.com/n24q02m/mcp-core/pull/146),
  [`9f3554d`](https://github.com/n24q02m/mcp-core/commit/9f3554dad9fe34517059612a6f3fcee7d338a62a))

- **storage**: Use sys.platform instead of platform.system() (avoid WMI hang)
  ([#147](https://github.com/n24q02m/mcp-core/pull/147),
  [`e928a45`](https://github.com/n24q02m/mcp-core/commit/e928a459e659c0faeb796dcf451c7d2c5ea0c48a))


## v1.13.0-beta.2 (2026-04-30)

### Bug Fixes

- **audit**: Remove redundant list comprehension (C416)
  ([#143](https://github.com/n24q02m/mcp-core/pull/143),
  [`eba6c64`](https://github.com/n24q02m/mcp-core/commit/eba6c64d6f0ed8ebecc39b364d5eae0a196b3645))

- **audit**: Ruff format multi_daemon_invariant.py
  ([#145](https://github.com/n24q02m/mcp-core/pull/145),
  [`fe76c44`](https://github.com/n24q02m/mcp-core/commit/fe76c44dd0a4512ef8922cf54f583bfdbd9cd210))

### Features

- **docs**: Canonical trust model doc ([#142](https://github.com/n24q02m/mcp-core/pull/142),
  [`12603b5`](https://github.com/n24q02m/mcp-core/commit/12603b5f46d4c6486c4d15678b38d831cad0b32e))


## v1.13.0-beta.1 (2026-04-30)

### Bug Fixes

- Address security + race conditions in relay transient helper
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- Drop listChanged key entirely in core-py bridge cache
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- Escape </script> in JS-context server_name interpolation
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- Strip null + listChanged=False core-py cache
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- **e2e**: Driver subprocess spawn cwd + pin :beta versions for stdio-direct
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- **storage**: Tampered-ciphertext test + dirname() + package re-export
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- **transport**: Daemon_relay_url returns root URL not /setup?token=
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- **transport**: Update TS JSDoc for daemonRelayUrl root URL behavior
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

### Features

- Add --kill-daemons flag to mcp-clean-state CLI
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- Add 2026-04-30 multi-mode migration document
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- Add docker-compose template for shared embedding-daemon
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- Add register_relay_form_tool transient HTTP helper for stdio mode
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- Add run_http_daemon alias + deprecate smart_stdio for stdio path
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- Add stdio-direct config type to E2E driver matrix
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- Trust model Phase 1 -- URL fix + PerPluginStore + multi-daemon CI
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- **audit**: Multi-daemon invariant CI check ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))

- **storage**: Per-plugin encrypted credential store
  ([#141](https://github.com/n24q02m/mcp-core/pull/141),
  [`4419df5`](https://github.com/n24q02m/mcp-core/commit/4419df503a96b7faf61225ead6caaa39e3827beb))


## v1.12.0 (2026-04-30)


## v1.12.0-beta.1 (2026-04-30)

### Bug Fixes

- Address security + race conditions in relay transient helper
  ([#140](https://github.com/n24q02m/mcp-core/pull/140),
  [`4531ec3`](https://github.com/n24q02m/mcp-core/commit/4531ec36b7b8eac1f6ba7db16f89bf782593337a))

- Drop listChanged key entirely in core-py bridge cache
  ([#140](https://github.com/n24q02m/mcp-core/pull/140),
  [`4531ec3`](https://github.com/n24q02m/mcp-core/commit/4531ec36b7b8eac1f6ba7db16f89bf782593337a))

- Escape </script> in JS-context server_name interpolation
  ([#140](https://github.com/n24q02m/mcp-core/pull/140),
  [`4531ec3`](https://github.com/n24q02m/mcp-core/commit/4531ec36b7b8eac1f6ba7db16f89bf782593337a))

- Strip null + listChanged=False core-py cache
  ([#140](https://github.com/n24q02m/mcp-core/pull/140),
  [`4531ec3`](https://github.com/n24q02m/mcp-core/commit/4531ec36b7b8eac1f6ba7db16f89bf782593337a))

### Features

- Add --kill-daemons flag to mcp-clean-state CLI
  ([#140](https://github.com/n24q02m/mcp-core/pull/140),
  [`4531ec3`](https://github.com/n24q02m/mcp-core/commit/4531ec36b7b8eac1f6ba7db16f89bf782593337a))

- Add 2026-04-30 multi-mode migration document
  ([#140](https://github.com/n24q02m/mcp-core/pull/140),
  [`4531ec3`](https://github.com/n24q02m/mcp-core/commit/4531ec36b7b8eac1f6ba7db16f89bf782593337a))

- Add docker-compose template for shared embedding-daemon
  ([#140](https://github.com/n24q02m/mcp-core/pull/140),
  [`4531ec3`](https://github.com/n24q02m/mcp-core/commit/4531ec36b7b8eac1f6ba7db16f89bf782593337a))

- Add register_relay_form_tool transient HTTP helper for stdio mode
  ([#140](https://github.com/n24q02m/mcp-core/pull/140),
  [`4531ec3`](https://github.com/n24q02m/mcp-core/commit/4531ec36b7b8eac1f6ba7db16f89bf782593337a))

- Add run_http_daemon alias + deprecate smart_stdio for stdio path
  ([#140](https://github.com/n24q02m/mcp-core/pull/140),
  [`4531ec3`](https://github.com/n24q02m/mcp-core/commit/4531ec36b7b8eac1f6ba7db16f89bf782593337a))

- Add stdio-direct config type to E2E driver matrix
  ([#140](https://github.com/n24q02m/mcp-core/pull/140),
  [`4531ec3`](https://github.com/n24q02m/mcp-core/commit/4531ec36b7b8eac1f6ba7db16f89bf782593337a))

- Multi-mode stdio direct architecture + relay helper
  ([#140](https://github.com/n24q02m/mcp-core/pull/140),
  [`4531ec3`](https://github.com/n24q02m/mcp-core/commit/4531ec36b7b8eac1f6ba7db16f89bf782593337a))


## v1.11.5 (2026-04-29)

### Bug Fixes

- Strip MCP_TRANSPORT + TRANSPORT_MODE from daemon spawn env (P0 fork-bomb)
  ([#135](https://github.com/n24q02m/mcp-core/pull/135),
  [`1eae40b`](https://github.com/n24q02m/mcp-core/commit/1eae40bd8a2adb8b9d3385f5c69aa25e9c92f5dc))


## v1.11.4 (2026-04-29)

### Bug Fixes

- Revert D18 eager-relay block in bridge (P0 spam tabs regression)
  ([#134](https://github.com/n24q02m/mcp-core/pull/134),
  [`3716bf0`](https://github.com/n24q02m/mcp-core/commit/3716bf0fd90e321defebd45f12606f32f29c7407))


## v1.11.3 (2026-04-29)

### Bug Fixes

- 5 code-review issues in Wave 10 eager relay (C1 lock collision, C2 wrong URL, I1 EPIPE, I2 sort
  order, I3 JSDoc) ([#133](https://github.com/n24q02m/mcp-core/pull/133),
  [`c39ba5f`](https://github.com/n24q02m/mcp-core/commit/c39ba5f369cfad028037d06b645e7879679da1b7))

- Add eagerRelaySchema option to runSmartStdioProxy in core-ts (D18.1)
  ([#131](https://github.com/n24q02m/mcp-core/pull/131),
  [`e2c003a`](https://github.com/n24q02m/mcp-core/commit/e2c003a5fc137afde432ed0245c62fe15b08ccce))

- Add None guard for cache in test_smart_stdio_cache to satisfy ty
  ([#128](https://github.com/n24q02m/mcp-core/pull/128),
  [`e74cccd`](https://github.com/n24q02m/mcp-core/commit/e74cccdd029dba41c5a9b53ce92af695a752a6ef))

- Advertise tools listChanged true in core-py capabilities cache
  ([#128](https://github.com/n24q02m/mcp-core/pull/128),
  [`e74cccd`](https://github.com/n24q02m/mcp-core/commit/e74cccdd029dba41c5a9b53ce92af695a752a6ef))

- Align iscoroutine to isawaitable in d17 wiring test
  ([#130](https://github.com/n24q02m/mcp-core/pull/130),
  [`f82cd2f`](https://github.com/n24q02m/mcp-core/commit/f82cd2f2ba69d0a004c3fffdb9e6f714c5bcc491))

- Cleanup _mcp_registry on run_local_server exit
  ([#130](https://github.com/n24q02m/mcp-core/pull/130),
  [`f82cd2f`](https://github.com/n24q02m/mcp-core/commit/f82cd2f2ba69d0a004c3fffdb9e6f714c5bcc491))

- Code quality fixes for D17 (registry leak + poller spawn order + sweep guard)
  ([#130](https://github.com/n24q02m/mcp-core/pull/130),
  [`f82cd2f`](https://github.com/n24q02m/mcp-core/commit/f82cd2f2ba69d0a004c3fffdb9e6f714c5bcc491))

- Core-ts eager relay + list_changed forwarding (D18.1 + D19)
  ([#131](https://github.com/n24q02m/mcp-core/pull/131),
  [`e2c003a`](https://github.com/n24q02m/mcp-core/commit/e2c003a5fc137afde432ed0245c62fe15b08ccce))

- Emit notifications/tools/list_changed via sentinel polling in core-py bridge
  ([#128](https://github.com/n24q02m/mcp-core/pull/128),
  [`e74cccd`](https://github.com/n24q02m/mcp-core/commit/e74cccdd029dba41c5a9b53ce92af695a752a6ef))

- Forward notifications/tools/list_changed through TS bridge (D19)
  ([#131](https://github.com/n24q02m/mcp-core/pull/131),
  [`e2c003a`](https://github.com/n24q02m/mcp-core/commit/e2c003a5fc137afde432ed0245c62fe15b08ccce))

- Nest companion cleanup inside successful unlink in sweep_stale_locks
  ([#130](https://github.com/n24q02m/mcp-core/pull/130),
  [`f82cd2f`](https://github.com/n24q02m/mcp-core/commit/f82cd2f2ba69d0a004c3fffdb9e6f714c5bcc491))

- Prevent eager relay OAuth AS lock from masking daemon discovery (C1)
  ([#133](https://github.com/n24q02m/mcp-core/pull/133),
  [`c39ba5f`](https://github.com/n24q02m/mcp-core/commit/c39ba5f369cfad028037d06b645e7879679da1b7))

- Refresh capabilities cache after credential write in core-py
  ([#128](https://github.com/n24q02m/mcp-core/pull/128),
  [`e74cccd`](https://github.com/n24q02m/mcp-core/commit/e74cccdd029dba41c5a9b53ce92af695a752a6ef))

- Refresh tools cache + emit list_changed in core-py bridge (D17)
  ([#128](https://github.com/n24q02m/mcp-core/pull/128),
  [`e74cccd`](https://github.com/n24q02m/mcp-core/commit/e74cccdd029dba41c5a9b53ce92af695a752a6ef))

- Start sentinel poller after daemon ready in run_smart_stdio_proxy
  ([#130](https://github.com/n24q02m/mcp-core/pull/130),
  [`f82cd2f`](https://github.com/n24q02m/mcp-core/commit/f82cd2f2ba69d0a004c3fffdb9e6f714c5bcc491))

- Test sweep companion cleanup behavior ([#130](https://github.com/n24q02m/mcp-core/pull/130),
  [`f82cd2f`](https://github.com/n24q02m/mcp-core/commit/f82cd2f2ba69d0a004c3fffdb9e6f714c5bcc491))

- Update forward-list-changed test for sync forwardDaemonMessageToBridge (I1)
  ([#133](https://github.com/n24q02m/mcp-core/pull/133),
  [`c39ba5f`](https://github.com/n24q02m/mcp-core/commit/c39ba5f369cfad028037d06b645e7879679da1b7))

- Use isawaitable + cast to satisfy ty type checker in D17.2 wrapper
  ([#129](https://github.com/n24q02m/mcp-core/pull/129),
  [`9ee00c2`](https://github.com/n24q02m/mcp-core/commit/9ee00c2922705e4bac245fe7ce8b8c83bc80035d))

- Wire D17.2 + D17.3 helpers into production paths
  ([#129](https://github.com/n24q02m/mcp-core/pull/129),
  [`9ee00c2`](https://github.com/n24q02m/mcp-core/commit/9ee00c2922705e4bac245fe7ce8b8c83bc80035d))

- Wire forwardDaemonMessageToBridge into production stdout writes
  ([#132](https://github.com/n24q02m/mcp-core/pull/132),
  [`7c91a94`](https://github.com/n24q02m/mcp-core/commit/7c91a945324a556f8010c1653b42427aeb0e707f))


## v1.11.2 (2026-04-29)

### Bug Fixes

- Enumerate Windows config.enc paths in mcp-clean-state CLI
  ([#127](https://github.com/n24q02m/mcp-core/pull/127),
  [`aa34d2c`](https://github.com/n24q02m/mcp-core/commit/aa34d2c1695fd8982837be7302629f178abd0ac0))


## v1.11.1 (2026-04-29)

### Bug Fixes

- Export registerOpenRelayTool from core-ts root + pass description to FastMCP
  ([#126](https://github.com/n24q02m/mcp-core/pull/126),
  [`79fa86b`](https://github.com/n24q02m/mcp-core/commit/79fa86b69b27bc50500df5e57776a0a6a9211e80))


## v1.11.0 (2026-04-29)

### Bug Fixes

- Prevent local information disclosure in sensitive config and lock files
  ([#124](https://github.com/n24q02m/mcp-core/pull/124),
  [`f17e5b9`](https://github.com/n24q02m/mcp-core/commit/f17e5b9c5950f452a68ca52396ef37955817c7ba))

- Remove Jules planning artifact from repo root
  ([`8b6545a`](https://github.com/n24q02m/mcp-core/commit/8b6545ae04d8aea175c61c2313615a2332668fa6))

- **deps**: Lock file maintenance ([#123](https://github.com/n24q02m/mcp-core/pull/123),
  [`0832ac4`](https://github.com/n24q02m/mcp-core/commit/0832ac47ff896e53c8846c96797dfda1d9f5b0e9))

- **deps**: Update dawidd6/action-send-mail action to v17
  ([#122](https://github.com/n24q02m/mcp-core/pull/122),
  [`40302c7`](https://github.com/n24q02m/mcp-core/commit/40302c7a16ae1895b6f06744543167a3422268a2))

- **deps**: Update non-major dependencies ([#121](https://github.com/n24q02m/mcp-core/pull/121),
  [`35a565a`](https://github.com/n24q02m/mcp-core/commit/35a565a8d45034710e415db97e0dbb715c8568a8))

### Features

- Transparent Bridge v2 — D6-D14 Wave 1 ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **auth**: Add secret + oauth_field schema flags (D7)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **auth**: Parity pre-fill renderer for core-ts (D7)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **auth**: Parity secret + oauthField flags for core-ts (D7)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **auth**: Pre-fill renderer with secret protection (D7)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **lifecycle**: Hybrid TTL lock sweep + cred_state metadata (D9)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **lifecycle**: Parity hybrid TTL sweep for core-ts (D9)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **relay**: Add single active form session token state (D11)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **relay**: Parity active form session for core-ts (D11)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **relay**: Parity register_open_relay_tool for core-ts (D6)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **relay**: Register_open_relay_tool helper (D6)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **scripts**: Add mcp-clean-state CLI (D14) ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **transport**: Bridge auto-respawn on daemon crash (D8)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **transport**: Parity bridge auto-respawn for core-ts (D8)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **transport**: Parity version-keyed cache for core-ts (D10)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))

- **transport**: Version-keyed tools cache + Windows-safe persist (D10, fixes crg #384)
  ([#125](https://github.com/n24q02m/mcp-core/pull/125),
  [`3fbd3a0`](https://github.com/n24q02m/mcp-core/commit/3fbd3a0f66b818fa64cc579d30c1b1f8630c1849))


## v1.10.0 (2026-04-28)

### Bug Fixes

- E2e driver tag default latest + add notion-oauth t3-staging tier
  ([#116](https://github.com/n24q02m/mcp-core/pull/116),
  [`1cf982f`](https://github.com/n24q02m/mcp-core/commit/1cf982fd9c364a880f9875ce425150e489f0f728))

- E2e driver tag default latest + add notion-oauth t3-staging tier
  ([#115](https://github.com/n24q02m/mcp-core/pull/115),
  [`7c2b2b2`](https://github.com/n24q02m/mcp-core/commit/7c2b2b248d55642837059cdb37e57d84edbaca4f))

- E2e driver tag default latest + add notion-oauth t3-staging tier
  ([#114](https://github.com/n24q02m/mcp-core/pull/114),
  [`3dfea8e`](https://github.com/n24q02m/mcp-core/commit/3dfea8e162a081a7f24c3e61ee9b07bfaa2cb296))

- **auth**: Correct schema field accessor 'name'->'key' + strict _setup_complete check
  ([#118](https://github.com/n24q02m/mcp-core/pull/118),
  [`f3b7497`](https://github.com/n24q02m/mcp-core/commit/f3b7497d328c40884cc1e990050435ee5a179969))

- **lint**: Biome format + ruff unused imports for transparent-bridge waves
  ([#119](https://github.com/n24q02m/mcp-core/pull/119),
  [`790c1fe`](https://github.com/n24q02m/mcp-core/commit/790c1fed20da1122831d981ec3d19cc3530a5999))

- **lint**: Ruff format pass for transparent-bridge waves
  ([#119](https://github.com/n24q02m/mcp-core/pull/119),
  [`790c1fe`](https://github.com/n24q02m/mcp-core/commit/790c1fed20da1122831d981ec3d19cc3530a5999))

- **lint**: Ruff format Wave 3 files ([#120](https://github.com/n24q02m/mcp-core/pull/120),
  [`a39f397`](https://github.com/n24q02m/mcp-core/commit/a39f397e5e6a0260979d7c5b4b12f3333036f521))

- **security**: Silence false-positive express-data-exfiltration on prefill copy
  ([#119](https://github.com/n24q02m/mcp-core/pull/119),
  [`790c1fe`](https://github.com/n24q02m/mcp-core/commit/790c1fed20da1122831d981ec3d19cc3530a5999))

- **stdio**: Bump startup_timeout default to 60s + MCP_STDIO_STARTUP_TIMEOUT env override
  ([#116](https://github.com/n24q02m/mcp-core/pull/116),
  [`1cf982f`](https://github.com/n24q02m/mcp-core/commit/1cf982fd9c364a880f9875ce425150e489f0f728))

- **stdio**: Bump startup_timeout default to 60s + MCP_STDIO_STARTUP_TIMEOUT env override
  ([#115](https://github.com/n24q02m/mcp-core/pull/115),
  [`7c2b2b2`](https://github.com/n24q02m/mcp-core/commit/7c2b2b248d55642837059cdb37e57d84edbaca4f))

- **stdio**: Strip MCP_TRANSPORT from daemon child env to prevent fork bomb
  ([#116](https://github.com/n24q02m/mcp-core/pull/116),
  [`1cf982f`](https://github.com/n24q02m/mcp-core/commit/1cf982fd9c364a880f9875ce425150e489f0f728))

- **stdio**: Strip MCP_TRANSPORT from daemon child env to prevent fork bomb
  ([#115](https://github.com/n24q02m/mcp-core/pull/115),
  [`7c2b2b2`](https://github.com/n24q02m/mcp-core/commit/7c2b2b248d55642837059cdb37e57d84edbaca4f))

- **stdio**: Timeout 60s + strip MCP_TRANSPORT to prevent fork bomb
  ([#115](https://github.com/n24q02m/mcp-core/pull/115),
  [`7c2b2b2`](https://github.com/n24q02m/mcp-core/commit/7c2b2b248d55642837059cdb37e57d84edbaca4f))

- **test**: Narrow read_config result before 'not in' (ty type check)
  ([#120](https://github.com/n24q02m/mcp-core/pull/120),
  [`a39f397`](https://github.com/n24q02m/mcp-core/commit/a39f397e5e6a0260979d7c5b4b12f3333036f521))

- **transport**: Auto-open browser at root URL not /authorize
  ([#117](https://github.com/n24q02m/mcp-core/pull/117),
  [`d4c37b4`](https://github.com/n24q02m/mcp-core/commit/d4c37b42696ab4f7ccc9873ad6d873a088565b85))

- **transport**: RunLocalServer auto-opens browser when no creds
  ([#116](https://github.com/n24q02m/mcp-core/pull/116),
  [`1cf982f`](https://github.com/n24q02m/mcp-core/commit/1cf982fd9c364a880f9875ce425150e489f0f728))

- **transport**: Use is_schema_complete() as auto-open gate in run_local_server
  ([#118](https://github.com/n24q02m/mcp-core/pull/118),
  [`f3b7497`](https://github.com/n24q02m/mcp-core/commit/f3b7497d328c40884cc1e990050435ee5a179969))

- **transport**: Use isSchemaComplete() as auto-open gate (core-ts parity)
  ([#118](https://github.com/n24q02m/mcp-core/pull/118),
  [`f3b7497`](https://github.com/n24q02m/mcp-core/commit/f3b7497d328c40884cc1e990050435ee5a179969))

### Features

- **auth**: Add is_schema_complete() helper for relay auto-open gate
  ([#118](https://github.com/n24q02m/mcp-core/pull/118),
  [`f3b7497`](https://github.com/n24q02m/mcp-core/commit/f3b7497d328c40884cc1e990050435ee5a179969))

- **auth**: Add isSchemaComplete() parity in core-ts
  ([#118](https://github.com/n24q02m/mcp-core/pull/118),
  [`f3b7497`](https://github.com/n24q02m/mcp-core/commit/f3b7497d328c40884cc1e990050435ee5a179969))

- **auth**: Mark _setup_complete=true after authorize_post + otp_handler succeed
  ([#118](https://github.com/n24q02m/mcp-core/pull/118),
  [`f3b7497`](https://github.com/n24q02m/mcp-core/commit/f3b7497d328c40884cc1e990050435ee5a179969))

- **auth**: Mark _setup_complete=true after authorizePost + otpHandler succeed (parity)
  ([#118](https://github.com/n24q02m/mcp-core/pull/118),
  [`f3b7497`](https://github.com/n24q02m/mcp-core/commit/f3b7497d328c40884cc1e990050435ee5a179969))

- **lifecycle**: 4-line lock format + parse/expiry helpers + sweep_stale_locks (core-py)
  ([#119](https://github.com/n24q02m/mcp-core/pull/119),
  [`790c1fe`](https://github.com/n24q02m/mcp-core/commit/790c1fed20da1122831d981ec3d19cc3530a5999))

- **lifecycle**: 4-line lock format + sweep + mtime refresh (core-ts parity)
  ([#119](https://github.com/n24q02m/mcp-core/pull/119),
  [`790c1fe`](https://github.com/n24q02m/mcp-core/commit/790c1fed20da1122831d981ec3d19cc3530a5999))

- **storage**: Add _setup_complete flag parity in core-ts
  ([#118](https://github.com/n24q02m/mcp-core/pull/118),
  [`f3b7497`](https://github.com/n24q02m/mcp-core/commit/f3b7497d328c40884cc1e990050435ee5a179969))

- **storage**: Add _setup_complete metadata flag + mark_setup_complete()
  ([#118](https://github.com/n24q02m/mcp-core/pull/118),
  [`f3b7497`](https://github.com/n24q02m/mcp-core/commit/f3b7497d328c40884cc1e990050435ee5a179969))

- **transparent-bridge**: Wave 2 — stale lock hardening (core-py + core-ts)
  ([#119](https://github.com/n24q02m/mcp-core/pull/119),
  [`790c1fe`](https://github.com/n24q02m/mcp-core/commit/790c1fed20da1122831d981ec3d19cc3530a5999))

- **transparent-bridge**: Wave 3 — fast-handshake stdio-proxy with capabilities cache
  ([#120](https://github.com/n24q02m/mcp-core/pull/120),
  [`a39f397`](https://github.com/n24q02m/mcp-core/commit/a39f397e5e6a0260979d7c5b4b12f3333036f521))

- **transport**: Cache_path_for_lock + persist/load_capabilities_cache + version validation
  ([#120](https://github.com/n24q02m/mcp-core/pull/120),
  [`a39f397`](https://github.com/n24q02m/mcp-core/commit/a39f397e5e6a0260979d7c5b4b12f3333036f521))

- **transport**: Handle_initialize / tools_list from capabilities cache
  ([#120](https://github.com/n24q02m/mcp-core/pull/120),
  [`a39f397`](https://github.com/n24q02m/mcp-core/commit/a39f397e5e6a0260979d7c5b4b12f3333036f521))

- **transport**: Schema-completeness gate + _setup_complete flag (Wave 1)
  ([#118](https://github.com/n24q02m/mcp-core/pull/118),
  [`f3b7497`](https://github.com/n24q02m/mcp-core/commit/f3b7497d328c40884cc1e990050435ee5a179969))

- **transport**: Sweep stale locks at startup + hourly mtime refresh background task
  ([#119](https://github.com/n24q02m/mcp-core/pull/119),
  [`790c1fe`](https://github.com/n24q02m/mcp-core/commit/790c1fed20da1122831d981ec3d19cc3530a5999))

- **transport**: Wire fast-handshake into stdio proxy + persist cache at daemon startup
  ([#120](https://github.com/n24q02m/mcp-core/pull/120),
  [`a39f397`](https://github.com/n24q02m/mcp-core/commit/a39f397e5e6a0260979d7c5b4b12f3333036f521))


## v1.9.0 (2026-04-28)

### Bug Fixes

- Replace Object.assign with explicit copy to silence Semgrep mass-assignment heuristic
  ([#113](https://github.com/n24q02m/mcp-core/pull/113),
  [`7e72458`](https://github.com/n24q02m/mcp-core/commit/7e72458757e82136514bb41d8d68fc520443470c))

### Features

- **auth**: POST /authorize/prefill endpoint for driver-only side-channel (closes #103)
  ([#113](https://github.com/n24q02m/mcp-core/pull/113),
  [`7e72458`](https://github.com/n24q02m/mcp-core/commit/7e72458757e82136514bb41d8d68fc520443470c))

- **auth**: POST /authorize/prefill endpoint — driver-only side-channel (closes #103)
  ([#113](https://github.com/n24q02m/mcp-core/pull/113),
  [`7e72458`](https://github.com/n24q02m/mcp-core/commit/7e72458757e82136514bb41d8d68fc520443470c))


## v1.8.2 (2026-04-28)

### Bug Fixes

- Add ty: ignore for downstream type checkers ([#101](https://github.com/n24q02m/mcp-core/pull/101),
  [`f6d3ef8`](https://github.com/n24q02m/mcp-core/commit/f6d3ef8a1688b249eaff55b7c2ac293126b123f0))

- Hard-filter browser-form prefill to matrix-declared skret_keys
  ([#100](https://github.com/n24q02m/mcp-core/pull/100),
  [`0edd57a`](https://github.com/n24q02m/mcp-core/commit/0edd57aa4912185c5cca3d5b39a3461a1e0c6792))

- Ruff lint cleanup for e2e driver (TimeoutError, import sort, type args)
  ([#99](https://github.com/n24q02m/mcp-core/pull/99),
  [`525e673`](https://github.com/n24q02m/mcp-core/commit/525e673cfb10e43eb22a8eea07112966cd986738))

- Run formatting on python file after fixing file permission bug
  ([#109](https://github.com/n24q02m/mcp-core/pull/109),
  [`34e0379`](https://github.com/n24q02m/mcp-core/commit/34e0379cbd10a43f366800c22c0147b523673512))

- Secure file and directory permissions for sensitive data
  ([#109](https://github.com/n24q02m/mcp-core/pull/109),
  [`34e0379`](https://github.com/n24q02m/mcp-core/commit/34e0379cbd10a43f366800c22c0147b523673512))

- Use cast() for AsyncClient stubs in oauth_client tests
  ([#102](https://github.com/n24q02m/mcp-core/pull/102),
  [`77b59da`](https://github.com/n24q02m/mcp-core/commit/77b59daa7615bdcdcb9a10576216c2d92aa06eaf))

- **auth**: Clear aria-invalid on input retry ([#110](https://github.com/n24q02m/mcp-core/pull/110),
  [`a847c4e`](https://github.com/n24q02m/mcp-core/commit/a847c4ecd96f961b8b150e48754e083dd54adade))

- **deps**: Pin pydantic <2.13 across core-py + embedding-daemon for cohere compatibility
  ([#112](https://github.com/n24q02m/mcp-core/pull/112),
  [`a763171`](https://github.com/n24q02m/mcp-core/commit/a7631714210e7ab405981d2a6b2f71d6c44d5984))

- **deps**: Update non-major dependencies ([#105](https://github.com/n24q02m/mcp-core/pull/105),
  [`96ddf37`](https://github.com/n24q02m/mcp-core/commit/96ddf379807c4671e718cff74a7764133b9d9763))

- **transport/smart-stdio**: Honor Mcp-Session-Id response header for Streamable HTTP
  ([#111](https://github.com/n24q02m/mcp-core/pull/111),
  [`c4d0666`](https://github.com/n24q02m/mcp-core/commit/c4d06668f9655ee7c9d9ddda772ed0c955ff75d6))

### Chores

- **deps**: Lock file maintenance ([#108](https://github.com/n24q02m/mcp-core/pull/108),
  [`aec0a99`](https://github.com/n24q02m/mcp-core/commit/aec0a99534c2306db7b45938cd8c4b0863c55878))

- **deps**: Pin dependencies ([#104](https://github.com/n24q02m/mcp-core/pull/104),
  [`3324965`](https://github.com/n24q02m/mcp-core/commit/33249659e3093974ae97a17a70347fc34ecd93d5))

- **deps**: Update actions/checkout action to v6
  ([#106](https://github.com/n24q02m/mcp-core/pull/106),
  [`71f7e9f`](https://github.com/n24q02m/mcp-core/commit/71f7e9fcc5f02e89b3266d967f9409ac37fb6141))

- **deps**: Update astral-sh/setup-uv action to v8
  ([#107](https://github.com/n24q02m/mcp-core/pull/107),
  [`793efa7`](https://github.com/n24q02m/mcp-core/commit/793efa7e645374e13bd534b1c2a3c68d0ada774a))


## v1.8.1 (2026-04-27)

### Bug Fixes

- Relax pydantic spec to >=2.9,<2.14 (loose-range intent)
  ([#98](https://github.com/n24q02m/mcp-core/pull/98),
  [`32bce70`](https://github.com/n24q02m/mcp-core/commit/32bce70083c77c5ef622e7700cab228d5704e2cf))


## v1.8.0 (2026-04-27)

### Bug Fixes

- E2e _poll_until_complete handles multi-key setupStatus
  ([`b6fbd39`](https://github.com/n24q02m/mcp-core/commit/b6fbd39f973d33ff523932667c8e2042b105e186))

- E2e driver T2 cascade — OAuth client, per-session HTTP transport, tool-name corrections
  ([`3b17733`](https://github.com/n24q02m/mcp-core/commit/3b177335e3dc3f8b9e5869be94f60b58062979b8))

- Restore email-outlook deployment=[local, remote]
  ([#96](https://github.com/n24q02m/mcp-core/pull/96),
  [`454ffbb`](https://github.com/n24q02m/mcp-core/commit/454ffbb652b188c7ecc8f9fa55c1c76022cdae18))

- Restore wet-full + mnemo-full to t2-interaction after per-sub GDrive
  ([`26c13f9`](https://github.com/n24q02m/mcp-core/commit/26c13f968f69fde21370c0ada740955aa1898064))

- Restrict e2e-t0 workflow GITHUB_TOKEN to read-only
  ([`f08170e`](https://github.com/n24q02m/mcp-core/commit/f08170e9e1ffe20bb5b98fa309e596fd11e1916e))

- Set secure directory permissions for sqlite credential store
  ([#91](https://github.com/n24q02m/mcp-core/pull/91),
  [`b30fea5`](https://github.com/n24q02m/mcp-core/commit/b30fea505fb82ad60ad2396b0a8ed8a56abf2dc2))

- **deps**: Update dependency cryptography to v47
  ([#87](https://github.com/n24q02m/mcp-core/pull/87),
  [`fa9b917`](https://github.com/n24q02m/mcp-core/commit/fa9b917ca8b6dc69c71875a086104a860e207342))

- **deps**: Update non-major dependencies ([#85](https://github.com/n24q02m/mcp-core/pull/85),
  [`d5ea96a`](https://github.com/n24q02m/mcp-core/commit/d5ea96acb88a448dd2c15dcbea87e5d6cd3d4301))

- **transport/smart-stdio**: Cancel SSE body before awaiting reader promise
  ([#89](https://github.com/n24q02m/mcp-core/pull/89),
  [`5bfb316`](https://github.com/n24q02m/mcp-core/commit/5bfb316e5b9f8d98fdea823c01377b6212adb5ba))

### Chores

- **deps**: Lock file maintenance ([#86](https://github.com/n24q02m/mcp-core/pull/86),
  [`a8cf561`](https://github.com/n24q02m/mcp-core/commit/a8cf5610a68a010472770cabca7a9fde61331289))

### Features

- Add focus-visible states and styling for dynamic info elements
  ([#88](https://github.com/n24q02m/mcp-core/pull/88),
  [`25cd4c9`](https://github.com/n24q02m/mcp-core/commit/25cd4c9c07070f28eb1609006c28d8b28d536a15))

- Add visual feedback for disabled inputs in credential form
  ([#90](https://github.com/n24q02m/mcp-core/pull/90),
  [`e51c270`](https://github.com/n24q02m/mcp-core/commit/e51c270693c3e4c555c30b2a4330ff90e63a3474))

- E2e driver browser-form flow for telegram-user multi-step OTP/2FA
  ([`93e3f5c`](https://github.com/n24q02m/mcp-core/commit/93e3f5c28e511e33f98bae3570b5a5fca08b7f24))

- E2e driver delegated-OAuth path
  ([`f945cce`](https://github.com/n24q02m/mcp-core/commit/f945cceb2f9db7edbfc3b2212953bee64aab1807))

- E2e driver device-code response handling + email-outlook config
  ([`a38bea8`](https://github.com/n24q02m/mcp-core/commit/a38bea8dc215c42b50e1f925e3531b0b4dacc690))

- E2e driver hardening + reclassify notion-oauth out of T2 matrix
  ([#95](https://github.com/n24q02m/mcp-core/pull/95),
  [`88ffde0`](https://github.com/n24q02m/mcp-core/commit/88ffde0399f29095f85e0f500fab8399ff706060))

- Optimize pollForResponses array find lookup ([#92](https://github.com/n24q02m/mcp-core/pull/92),
  [`735a7ec`](https://github.com/n24q02m/mcp-core/commit/735a7ec0b820ab9a0d723941ea75fa4d4a1b1aac))

- Prefill credential form fields from OAuth query params
  ([#97](https://github.com/n24q02m/mcp-core/pull/97),
  [`651c47d`](https://github.com/n24q02m/mcp-core/commit/651c47dc76b4f0d1e51d5678622d22c0cf89e765))


## v1.8.0-beta.1 (2026-04-27)

### Bug Fixes

- Correct T0 commands for web-core (uv pytest) and claude-plugins (validate script)
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- E2e .skret.yaml + bootstrap with explicit provider/region overrides
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- E2e bootstrap uses aws ssm directly + botocore[crt]
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- E2e driver T0 robustness across monorepo + Windows nested-uv envs
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- E2e driver t0/all sweeps spawn fresh subprocess per config
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- E2e-t0 CI workflow needs PYTHONPATH=.. for e2e package resolution
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- E2e-t0 workflow setup + semgrep nosemgrep on jinja2 yaml renderer
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Include imagine-mcp in downstream auto-issue cascade
  ([#84](https://github.com/n24q02m/mcp-core/pull/84),
  [`72af2a2`](https://github.com/n24q02m/mcp-core/commit/72af2a2b16b68ac6b7dc79ed649133d082e695f0))

- Place semgrep nosemgrep on same line as jinja2.Environment call
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Route /mcp through per-session transport map (TS parity with Python)
  ([`77419e7`](https://github.com/n24q02m/mcp-core/commit/77419e7c5ac4301bca6cafc4574dc1e5f641c710))

- Strip UV_/VIRTUAL_ENV when spawning T0 subprocess
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Sweep doppler/infisical refs to skret SSM
  ([`ce8facd`](https://github.com/n24q02m/mcp-core/commit/ce8facd43b31b559f908c7dbde1d3813adfba99f))

### Features

- Add compose renderer for e2e driver ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Add docker-compose Jinja templates for 8 MCP servers
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Add e2e bootstrap script + Makefile + T0 CI workflow + driver precommit hook
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Add e2e driver orchestrator CLI ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Add e2e matrix yaml with 16 configs (3-axis taxonomy)
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Add ephemeral port allocator for e2e driver ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Add MCP client runner and user gate for e2e driver
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Add relay form filler via httpx for e2e driver
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Add skret SSM loader for e2e driver ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Bootstrap mcp-core e2e driver skeleton ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- E2e framework driver (T0+T2 2-tier, 16-config matrix)
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))

- Lock in per-authorize sub uniqueness contract for local_oauth_app
  ([#94](https://github.com/n24q02m/mcp-core/pull/94),
  [`df0f582`](https://github.com/n24q02m/mcp-core/commit/df0f582952eabaca76ec5311b728c585743444af))


## v1.7.6 (2026-04-24)

### Bug Fixes

- Replace httpx_sse with local SSE parser to preserve Accept header
  ([`1b9908d`](https://github.com/n24q02m/mcp-core/commit/1b9908d580f91571a6f2ccfdd02ac5ffc1224e44))

- Reset stale setupStatus entries on every POST /authorize submit
  ([#83](https://github.com/n24q02m/mcp-core/pull/83),
  [`a159f2f`](https://github.com/n24q02m/mcp-core/commit/a159f2fb3f162217949419d7ce4348f2b0086349))


## v1.7.5 (2026-04-24)

### Bug Fixes

- Narrow relay_schema to non-None before create_local_oauth_app
  ([`c2cb2ab`](https://github.com/n24q02m/mcp-core/commit/c2cb2ab0849046cd9718d8f78be596f34b9bb67d))


## v1.7.4 (2026-04-24)

### Bug Fixes

- Re-loosen pydantic pin after Renovate revert
  ([`1a1e3c5`](https://github.com/n24q02m/mcp-core/commit/1a1e3c51ec8e4b88b69f539d453f1200e33c04fa))


## v1.7.3 (2026-04-24)

### Bug Fixes

- Narrow next_step type for downstream strict ty check
  ([`6b8a8da`](https://github.com/n24q02m/mcp-core/commit/6b8a8dade8c956ee52bd2f71f45e6257998acf02))


## v1.7.2 (2026-04-24)

### Bug Fixes

- **deps**: Update non-major dependencies ([#81](https://github.com/n24q02m/mcp-core/pull/81),
  [`57fceaf`](https://github.com/n24q02m/mcp-core/commit/57fceafe013fa9f12c87835c591f4c9e65d177a2))

### Chores

- **deps**: Lock file maintenance ([#82](https://github.com/n24q02m/mcp-core/pull/82),
  [`eaae873`](https://github.com/n24q02m/mcp-core/commit/eaae873947107fe9264b2f23cc812cf85f725f3b))


## v1.7.1 (2026-04-24)

### Bug Fixes

- Loosen pydantic pin to accommodate cohere 6.1.x
  ([`e9fe4df`](https://github.com/n24q02m/mcp-core/commit/e9fe4df59214a3f86b97e3ac6a11e6ccf45572a7))


## v1.7.0 (2026-04-24)

### Bug Fixes

- Smart stdio proxy SSE session handling + Accept header + OAuth redirect
  ([`09e05db`](https://github.com/n24q02m/mcp-core/commit/09e05dbb16a1e7b9b40f98e8e9b7e5cd7606b0f8))

- Smart-stdio TS parity for SSE session + Accept header
  ([`0b7127d`](https://github.com/n24q02m/mcp-core/commit/0b7127d117a12fb44f50df5b0c49a2b0eaaef9e8))

- **deps**: Update non-major dependencies ([#77](https://github.com/n24q02m/mcp-core/pull/77),
  [`ee35ceb`](https://github.com/n24q02m/mcp-core/commit/ee35ceb210495bf6a7c01f775b46052a6583d040))

- **stdio**: Use CREATE_NO_WINDOW on Windows instead of DETACHED_PROCESS
  ([`9adda23`](https://github.com/n24q02m/mcp-core/commit/9adda23990775f87c58c85bebed2defde4f14d8b))

### Chores

- **deps**: Update astral-sh/setup-uv action to v8
  ([#78](https://github.com/n24q02m/mcp-core/pull/78),
  [`a6b53ea`](https://github.com/n24q02m/mcp-core/commit/a6b53eaf721d8aed5f2ded3231e1ac8acaea0175))

- **deps**: Update semgrep/semgrep docker digest to 7810f1d
  ([#76](https://github.com/n24q02m/mcp-core/pull/76),
  [`0ae11b3`](https://github.com/n24q02m/mcp-core/commit/0ae11b3d15c33960ae1ce36c9c2158e85a2b5aa4))

### Features

- Add focus-visible styles to TS credential form
  ([#80](https://github.com/n24q02m/mcp-core/pull/80),
  [`9664947`](https://github.com/n24q02m/mcp-core/commit/96649472d5f47a517671281e7722f249c950b820))

- Cache TextEncoder and TextDecoder in crypto routines
  ([#79](https://github.com/n24q02m/mcp-core/pull/79),
  [`85cd02e`](https://github.com/n24q02m/mcp-core/commit/85cd02e668f42d52331a33d42518f40b9e3fc7ba))

- Implement Smart Daemon Manager for stdio proxy
  ([`3581ae5`](https://github.com/n24q02m/mcp-core/commit/3581ae57c20d54178087564a9656407398467a7c))

- **core-ts**: Implement Smart Stdio Proxy (1-Daemon architecture)
  ([`a5bb7bc`](https://github.com/n24q02m/mcp-core/commit/a5bb7bcb4eef146dc9c7dbe6323c4f5b23b64ef3))


## v1.6.3 (2026-04-22)

### Bug Fixes

- Relay credential form must follow redirect_url on success
  ([#75](https://github.com/n24q02m/mcp-core/pull/75),
  [`6bc74e8`](https://github.com/n24q02m/mcp-core/commit/6bc74e88536ca232c9f4a524f0a77f0bac6f047c))


## v1.6.2 (2026-04-22)

### Bug Fixes

- Propagate sub in delegated OAuth + add DCR endpoint
  ([#74](https://github.com/n24q02m/mcp-core/pull/74),
  [`086a874`](https://github.com/n24q02m/mcp-core/commit/086a8744ba55ee0c580870d83e8c24d4485f4699))


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
