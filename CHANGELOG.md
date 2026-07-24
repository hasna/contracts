# Changelog

All notable changes to `@hasna/contracts` are documented here.

## [0.5.4] - 2026-07-24

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
- Bumped `0.5.3 -> 0.5.4`: `0.5.3` is reserved for the reconcile-only release
  below (documented but not yet published); this security fix ships as `0.5.4`,
  strictly above the published npm `latest` (`0.5.2`). `kitVersion` in
  `hasna.contract.json` is synced to `0.5.4` to match `package.json`.

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
