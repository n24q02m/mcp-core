# CHANGELOG

<!-- version list -->

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
