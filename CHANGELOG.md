# Changelog

All notable changes to `@hasna/contracts` are documented here.

## [0.8.2] - 2026-07-27

### `no-cloud-scan` no longer reports its own denylist as the consumer's breach

- `FORBIDDEN_SHARED_CLOUD_RUNTIMES` is a pair of string literals, so any repo
  that imports `@hasna/contracts` without externalising it gets the denylist
  **inlined into its build output**. The scanner then matched its own denylist in
  the consumer's artifact and failed the gate — permanently, with nothing the
  consumer could remove to fix it. The tell was `open-cloud` being reported
  against repos that never used it. Measured on a real bundle: two module names
  present with **zero** import specifiers, both dropping to zero when
  `@hasna/contracts` is externalised. All eight runtime patterns leak this way,
  not only the two module names.
- Build output is now judged by what it still **resolves** — import specifiers —
  and by dependency edges, never by bare mentions. `package.json` and `bun.lock`
  checks are untouched, and an externalised `import { … } from "@hasna/cloud"`
  survives bundling verbatim, so it is still a critical finding in `dist/`.
- The exemption is for **generated modules only**: a file must be both under a
  build-output directory (`bin`, `dist`, `build`, `out`, `.output`) and a
  bundler-emitted `.js`/`.ts` family file. `lib/` is authored in too many repos
  to count as output, and a hand-written `bin/deploy.sh` that sets
  `HASNA_CLOUD_*` is still a finding — the one pattern kind with no import to
  look for keeps its coverage.
- The declaration-file exemption no longer returns early for the whole file, so a
  **real import inside a declaration file is no longer exempt**. That was a false
  negative in 0.8.1: such a scan passed on the `v0.8.1` tag and now fails with
  `(module import)`.
- `CONTRACTS_DECLARATION_PATHS` shrank from nineteen hand-listed paths to the two
  authored sources. Enumerating every `dist/` bundle by hand was what made the
  bug possible: the list could only ever describe this package's own output,
  never a consumer's, which is where the declaration actually lands.

### `scripts/mutation-audit.ts` can measure again, and no longer corrupts the tree

- The audit parsed `bun test` output with `/^\s*(\d+) pass$/m`. With
  `FORCE_COLOR` set — common in terminals and agent harnesses — Bun emits ANSI
  into a pipe, nothing matched, and **every mutation scored `NO-RESULT` while the
  run still exited 0**. The suite is now spawned with colour disabled, escapes
  are stripped regardless, and a baseline reporting zero passes is a hard failure
  instead of a silent pass-through.
- The audit edits tracked source in place. It now records the original to a
  gitignored sentinel *before* mutating and repairs an abandoned mutation on the
  next run, because signal handlers cannot cover `SIGKILL` or a process-group
  kill — which is how `if (false) roots.push(...)` reached a commit.

## [0.8.1] - 2026-07-27

### `no-cloud-scan` matches dependency edges and real imports, not substrings

- `no-cloud-scan` previously matched its runtime patterns as bare substrings of
  raw file text, so a dependency edge, a string naming a package, and a comment
  saying the package had been *removed* all scored the same. Already-remediated
  repos therefore failed the gate: `@hasna/connectors@1.4.0` reported on a JSDoc
  line recording a removed import and on the boundary guard test that the
  remediation pattern itself mandates.
- Comments are masked before matching, string-, template- and regex-aware and
  UTF-16 aligned, failing open to the raw text when the parse is detectably
  lost. `.json`, `.jsx` and `.tsx` are never masked, because guessing their
  comment syntax would cost a false negative.
- The mandated boundary guard test is allowlisted once, for module *mentions*
  only. Config patterns are never exempt, and any computed `import`/`require` —
  identifier, backtick, template, or concatenation — withdraws the exemption.
- `registerCloudTools`/`registerCloudCommands` are scoped to bindings imported
  from a forbidden module, with name matching retained in files that have no
  imports to read.
- `package.json` and `bun.lock` are read for the actual dependency edge: every
  install-bearing section on both sides, every workspace seeded, `npm:` aliases
  followed in both directions, and specifiers matched by path segment.
- Finding messages gained a reason suffix (`(module import)`,
  `(source reference)`), which `src/conformance.ts` splices into the
  `no_cloud_guard` detail — so conformance report text changes, while the
  schema, the verdicts and the exit-code semantics do not.
- Known residual gap: a specifier split across a concatenation, such as
  `import("@hasna/" + "cloud")`, is not detected, because the module name never
  appears contiguously. Substring matching did not catch this either.

## [0.8.0] - 2026-07-26

### Explicit storage-engine waivers (additive, v1)

- Add `metadata.conformance.waivedStorageEngines`, an auditable storage waiver
  that mirrors the existing surface-waiver pattern:
  `{ engine, reason, reviewedBy?, expiresAt? }`, typed and unique per engine
  with a non-empty reason.
- A waiver-eligible `cli-with-store` repo may now declare `storage.engines:
  ["sqlite"]` when `postgres` carries a waiver, instead of fabricating
  PostgreSQL support to pass the gate. Only `postgres` is waivable — SQLite
  stays the non-waivable local source of truth.
- A waiver is refused for every manifest that already claims PostgreSQL is in
  play: `service` and `saas` classes, a `cli-with-store` shipping
  `<name>-serve`, `storage.mode: "cloud"` (which reads and writes PostgreSQL
  directly), the `cloud` runtime placement, and the `hasna-saas` product story.
  `self_hosted` placement stays eligible, because `storage.mode` is what decides
  the backing engine. Eligibility is computed once by the exported
  `storageWaiverIneligibilityReason()` and shared by the schema and the gate, so
  the two layers cannot drift.
- Waiver `reason` and `reviewedBy` are echoed into the conformance report, which
  is an audit artifact, so they reject control characters and are bounded to 500
  and 200 characters. A reason or reviewer carrying a private infrastructure
  reference is redacted in the report rather than echoed, including for
  `manifestTier: "private"` callers where `public_manifest_safety` is skipped.
- `storage_capabilities` passes a waived repo with a detail such as
  `sqlite declared; postgres explicitly waived: <reason>`, mirroring the
  `surface_matrix` "declared or explicitly waived" wording. It fails an
  ineligible waiver, a waiver for a non-waivable engine, and an expired
  waiver (`expiresAt` in the past), so a time-boxed exception cannot silently
  become permanent.
- `storage.pgTestGate` and `storage.envPrefix` are now required only when
  PostgreSQL is actually in play. Both exist to serve the PostgreSQL contract
  (the live-PG proof and the `HASNA_<NAME>_DATABASE_URL` derivation), so a
  validly waived PostgreSQL engine no longer demands them. A waiver next to a
  declared `postgres` engine is redundant and does not remove either
  obligation.
- Expiry is evaluated by conformance, not by the schema, so a lapsed waiver
  keeps the manifest parseable and reports one clear storage failure — renew or
  declare — instead of invalidating every other check or also demanding the
  engine, its env prefix, and its live-PG gate.
- A waiver whose `reason` or `reviewedBy` carries a private infrastructure
  reference fails the gate rather than being echoed or silently redacted: an
  exception nobody can read is not auditable.
- An ineligible waiver on a manifest that is otherwise missing the engine is
  refused by the schema, and the `manifest_valid` message now names the refusal
  reason — the parse aborts before the gate runs, so it is the only place that
  can explain why the escape hatch did not apply.
- The shipped JSON Schema (`hasna.contract.schema.json`) matches the Zod schema
  field for field: `engine` is narrowed to the waivable set, `maxItems` enforces
  one waiver per engine, and the control-character and length rules are
  mirrored. New exports: `StorageEngineWaiverSchema`,
  `storageWaiverIneligibilityReason()`, the `WAIVABLE_STORAGE_ENGINES` tuple,
  and the two length constants.

- `runRepoConformance` accepts an optional `now` clock so time-boxed checks such
  as waiver expiry are deterministically testable.

### Compatibility

- Additive for verdicts. A manifest without `waivedStorageEngines` is validated
  and gated exactly as in `0.7.1`; every existing check id, status, and pass
  detail is unchanged, verified by a byte-for-byte report comparison against
  `0.7.1` over a no-waiver manifest corpus.
- Three caveats. The `manifest_valid` *failure* detail for a sqlite-only
  `cli-with-store` now names the waiver mechanism, so a CI job asserting the old
  exact message needs updating. `metadata.conformance` has always carried
  `catchall`, so a repo that already used a `waivedStorageEngines` key with
  different semantics now has it interpreted, failing closed when it is
  ineligible. And, as with `waivedSurfaces`, the field carries `.default([])`,
  so `ServiceContractMetadata`'s *output* type gains a required
  `waivedStorageEngines` property for TypeScript callers constructing it.
- Most existing `cli-with-store` repos stay ineligible for now because they ship
  `<name>-serve`. Widening the waiver later is backwards-compatible; narrowing
  it after repos have banked a green build is not, so v1 covers only the shape
  nobody disputes — CLI-only, `local` storage mode, SQLite.
- Dependents upgrading from `0.7.0` rather than `0.7.1` also pick up the
  execution-free `secure-local-store` boundary from `0.7.1`, which removed the
  execution-ful exports. This release is the `0.8.0` reconcile that
  `docs/architecture/factory-v1-contract-spec.md` called for.

## [0.7.1] - 2026-07-24

### PR-drain finalize (release republish)

- Republish the current `main` line. The `0.7.0` npm artifact was cut before
  PR #24 (`fix: restore execution-free contracts boundary`) and PR #25
  (Factory v1 contract spec docs) merged, so the published `0.7.0` tarball did
  not carry those changes; `0.7.1` ships `main` HEAD including them.
- The execution-free `secure-local-store` boundary restore (PR #24) — the
  package and CLI expose only declarative policy/profile/proof metadata, with
  the `contracts-cli` bin pointing at the declarative entry — is now published.

## [0.7.0] - 2026-07-24

### Service contract capability extensions (additive, v1)

- Add typed `serviceSurfaces` for API, SDK, MCP, and CLI, with class- and
  profile-scoped waivers plus package export/bin conformance
  (`surface_matrix`, `surface_bindings`).
- Add SQLite/PostgreSQL storage-engine capability metadata, `.db` path
  validation, and live-Postgres test-gate metadata recorded (never executed)
  by conformance (`storage_capabilities`).
- Add product `hosting` stories (`user-hosted` / `hasna-saas`) and canonical
  `self_hosted` runtime placement; the legacy `self-hosted` spelling parses as
  a deprecated alias.
- `public_manifest_safety` conformance rejects secret/credential references,
  credential-shaped values, internal hosts, ARNs, and account IDs from public
  manifests, reporting only structural path + category (no value echo).

### Client transport hardening

- Reject leading-zero, zero, and out-of-range explicit ports before WHATWG URL
  normalization, preserving canonical DNS, IPv4, bracketed IPv6, loopback,
  default, and boundary ports.
- Reject `Host`, `:authority`, `Forwarded`, `X-Forwarded-Host`, and
  `X-Original-Host` overrides case-insensitively in default and per-call
  authenticated headers before auth assembly or fetch.
- Fail closed on authenticated redirects: every 3xx is surfaced as a terminal
  `HasnaHttpError` so API keys, bearer credentials, headers, and bodies stay on
  the validated origin.
- Compose the cloud host from `HASNA_FLEET_API_DOMAIN` with a neutral,
  non-resolving placeholder fallback that marks the config `misconfigured`.

### Current-main repair

- Make `secure-local-store` execution-free. The package and CLI expose only
  declarative policy/profile/proof metadata; filesystem scanning, permission
  changes, retention, deletion, SQLite access, and maintenance stay with each
  owning package.
- Close composed-path public-manifest bypasses such as nested `api.key`,
  `access.key`, and `database.url` while preserving redacted structural
  diagnostics and flattened separator variants.
- Require supported service APIs to declare `GET /health`, `GET /ready`, and
  `GET /version`; require a root self-host artifact for service, SaaS, and
  `cli-with-store` repos that ship a serve bin; require SaaS
  `storage.envPrefix`.
- Keep CLI-only `cli-with-store` repos CLI-only for surface conformance instead
  of forcing API, SDK, or MCP declarations.
- Ship `contracts` and `contracts-cli` through distinct packed member paths so
  the package tar has no duplicate raw/effective path.

### Compatibility

- Legacy v1 manifests without explicit surfaces remain schema-readable. The
  intentional schema tightenings reject a declared non-`.db` SQLite path, SaaS
  storage without `envPrefix`, and supported APIs without the three canonical
  GET endpoints. Conformance is intentionally stricter than schema parsing and
  reports migration gaps without executing manifest commands.

## [0.6.1] - 2026-07-24

### Security — remove internal infra hostnames from the published package

The published bundle baked a real internal-infra hostname template
(`https://<app>.<internal-domain>`) into `defaultCloudBaseUrl()`, which every downstream
`@hasna/*` client inherits via `resolveClientTransport()` whenever
`HASNA_<APP>_API_KEY` is set but no explicit `HASNA_<APP>_API_URL` is provided.

- `defaultCloudBaseUrl(name)` now composes `https://<app>.<domain>` where
  `<domain>` comes from the new `HASNA_FLEET_API_DOMAIN` env var (required for a
  real deployment) — exported via the new `fleetApiDomain()` helper. Absent (or
  blank/malformed/app-prefix-incompatible) configuration falls back to a neutral,
  non-resolving placeholder (`your-deployment.example`) and marks the resolution
  `misconfigured: true`, so authenticated clients fail before making a request
  instead of guessing a real internal hostname.
- `toV1BaseUrl()` now rejects credentials/userinfo, IDN/punycode, non-canonical
  IP forms, parser-normalized authorities, query strings, and fragments; HTTP is
  accepted only for exact loopback authorities.
- Authenticated transport requests use `redirect: "manual"`: every 3xx (including
  same-origin) fails closed as a `HasnaHttpError`, so API keys, bearer
  credentials, custom headers, and bodies never cross an authority boundary via
  runtime redirect behavior.
- Added `tests/published-package-security.test.ts` — scans tracked sources, build
  output, and the actual packed tarball (across case/percent/unicode/hex/base64/
  UTF-16 encodings and raw tar members) for forbidden internal domains, and
  asserts source/dist/packed version provenance.
- Bumped to `0.6.1`: `0.5.3` is reserved for the reconcile-only release below and
  `0.6.0` for the feature line already on `main` (both documented but not yet
  published; npm `latest` is `0.5.2`). This security fix ships as `0.6.1`,
  strictly above every reserved version. `kitVersion` in `hasna.contract.json` is
  synced to `0.6.1` to match `package.json`.

## [0.5.3] - 2026-07-24

### Registry <-> git reconciliation (main was diverged from the published npm line)

Before this release, the git history and the npm registry had silently diverged and
**no git tags existed to anchor any published version**. This release reconciles the two
lines. Investigation of the published artifacts (via `npm pack`) established the following
ground truth:

- **npm `latest` was `0.5.2`** (published 2026-07-08), but its `package.json` `gitHead`
  (`591933033e0f9e252a8161ca61d05598613cca15`) **does not exist anywhere in the repo** — an
  orphaned / out-of-band build.
- **`main` was at `0.5.1`, a version that was never published.** npm jumped `0.4.2 -> 0.5.2`,
  skipping `0.5.0` and `0.5.1`.
- Comparing the published `0.5.2` tarball against a build of `origin/main`
  (`c61d6b4`) showed the source is **content-identical**: every emitted `*.d.ts` and the
  shipped `src/kit` templates match byte-for-byte, and the only real delta is the
  `CONTRACTS_PACKAGE_VERSION` constant (`"0.5.1"` on main vs `"0.5.2"` published). Remaining
  `dist/*.js` differences were pure build-environment noise (pnpm vs bun `node_modules`
  path comments in vendored code). **No product code was lost; `0.5.2` was `main` + a version
  bump, published out-of-band without a commit or tag.**
- The same pattern was confirmed for **`0.4.2`** (published 2026-07-06): content-identical to
  commit `e4baf61` (the `0.4.1` commit) except for the version constant. Also an out-of-band
  publish.
- Versions present in git but **never published**: `0.3.0`, `0.5.0`, `0.5.1`.

### Changed

- **Bumped version `0.5.1 -> 0.5.3`** so the package version is strictly above the published
  npm `latest` (`0.5.2`). `0.5.1` and `0.5.2` are intentionally not reused.
- **Synced `CONTRACTS_PACKAGE_VERSION` in `src/schemas.ts` to `0.5.3`** to match
  `package.json`. (This constant is a hardcoded literal that must be kept in lockstep with
  `package.json`; keeping them out of sync is what let the out-of-band builds ship a version
  the git history never recorded. See "Follow-ups".)

### Tags backfilled (registry <-> git anchors)

Annotated tags were created so every published npm version is anchored to a commit:

| npm version | git anchor | note |
|---|---|---|
| 0.1.0 | efcdd68 | exact version-bump commit |
| 0.1.1 | 3ca1644 | exact |
| 0.2.0 | 42ef93e | exact |
| 0.2.1 | a531712 | exact |
| 0.2.2 | e4d5b63 | exact |
| 0.4.0 | 42a1287 | exact |
| 0.4.1 | e4baf61 | exact |
| 0.4.2 | e4baf61 | out-of-band build; content-equivalent to 0.4.1 commit + version bump |
| 0.5.2 | c61d6b4 | out-of-band build; content-equivalent to main HEAD + version bump; original gitHead orphaned |

### Follow-ups (to prevent silent divergence)

- **Always `git tag vX.Y.Z` on publish** and verify the published `gitHead` resolves inside
  the repo before every future publish.
- Consider deriving `CONTRACTS_PACKAGE_VERSION` from `package.json` at build time (or a
  release check that asserts they match) so the constant can never drift from the published
  version again.
- Open PRs that target versions at or below this reconciled baseline (`#21 -> 0.5.1`,
  `#14 -> 0.4.2`, `#13`/`#7 -> 0.4.1`, and `#18 -> 0.5.3`) must be re-bumped **above 0.5.3**;
  `#22` and `#19` both claim `0.6.0` and collide with each other.
