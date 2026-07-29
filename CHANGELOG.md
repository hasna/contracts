# Changelog

All notable changes to `@hasna/contracts` are documented here.

## Unreleased

### Tests: direct Todos operation and invariant coverage

Added focused unit coverage for the operation manifest's schema and semantic
guards, operation lookup misses, invariant-registry integrity, and invariant
lookup hits and empty results. `src/no-cloud.ts` was not duplicated here because
its exported scanner and declaration masker already have extensive direct edge
coverage in `tests/no-cloud-edge.test.ts`.

### Credential resolution: env holds a pointer, disk holds the secret, resolved at call time

MEASURED FAILURE THIS KILLS. A tmux shell started before a key rotation held the
stale `HASNA_ACCOUNTS_API_KEY` for its whole life; every command from it failed
`401 "API key has been revoked"`, while a fresh login shell on the same machine
in the same second returned `200`. The credential on disk was correct
throughout — only the process env was stale. Environment variables are a
snapshot taken at process start; credentials are mutable state.

`resolveClientTransport()` stays the entry point and gains a credential provider
chain resolved on every call: an explicit `--api-key`/`--profile` argument, then
a deliberate `HASNA_<NAME>_API_KEY_OVERRIDE` / `HASNA_PROFILE` pointer, then
**disk** (`$HOME/.hasna/cloud/<name>.env`, then
`$HOME/.config/hasna/<name>-cloud.env`), and finally the legacy
`HASNA_<NAME>_API_KEY` process env — demoted to a deprecated fallback used only
when the disk yields nothing. That demotion is what fixes stale shells
immediately, without waiting for shells to cycle. See CONTRACT.md §3a.

WHAT WAS DELIBERATELY NOT BUILT: env-first with a retry-on-401 that re-reads
disk. In mature CLIs retry-on-401 signals two-tier auth — a durable secret
minting short-lived tokens. With a single static key it makes identity
nondeterministic per call and, the correctness bug, SILENTLY RESCUES A REVOKED
DELIBERATE OVERRIDE as the wrong principal. A deliberate tier therefore never
falls through, and `401`/`403` are terminal regardless of retry policy.

THE BACKEND DECISION STAYS ENDPOINT-GATED. A client routes to the network only
when an API URL is configured in the environment, so a credential file on disk
can never by itself flip a client that reads its sqlite store. What the chain
DOES supply is the credential half of the fleet flip signal: with a URL set and
no explicit `HASNA_<APP>_STORAGE_MODE`, a key resolved from ANY tier — including
one that exists only on disk — infers the `postgres` backend. Resolving that half
from `HASNA_<APP>_API_KEY` alone would have left the exact migration this change
recommends (endpoint in the environment, credential on disk) reading the local
dataset with `misconfigured: false` and no warning. `HOME` is read from the same
env object the caller passes, so an env without `HOME` performs no disk read at
all and the behaviour stays hermetic.

Also fixed: `createClientTransport()` re-read the API key straight out of `env`,
a second resolution path that diverged from `resolveClientTransport()` on the
code path most consumers actually take. Both now share the chain, and
`createHasnaHttpTransport()` accepts a provider so rotation heals inside
long-lived processes without rebuilding the client — resolved once per request,
never per retry attempt, so one request is always one identity.

New conformance check `credential_seam_compliance` fails any repo that resolves
a client credential by hand. It derives the names it polices from
`clientTransportEnvKeys()` so it cannot drift from the seam, matches read
expressions only, and structurally excludes server-side `*_SERVE_API_KEY` /
`*_BOOTSTRAP_API_KEY` reads and third-party keys wearing the `HASNA_` prefix.

#### Fixed: a plaintext key leak on the most-used public entry point

`createHasnaHttpTransport({ apiKey })` accepts a bare string, and that branch
built its credential as a plain object literal — running NEITHER the
header-byte check NOR the seal. A key carrying a CR therefore reached `fetch`,
which rejects it with a `TypeError` that quotes the whole header value:

```
TypeError: Header 'x-api-key' has invalid value: 'AAAA\nhasna_todos_SUPERSECRET-VALUE'
```

That is the exact failure `ILLEGAL_IN_HEADER_VALUE` and CONTRACT.md §3a were
added to close; the first test round only ever exercised `resolveCredential()`,
so the public constructor was unprotected and untested. Credentials are now
built by exactly two constructors — `resolveCredential()` for the chain and the
new exported `explicitCredential()` for a caller-supplied string — and both
validate and seal. There is no third construction site.

#### Fixed: `credential_seam_compliance` was quietly weakened below its own documentation

Two exclusions had been widened past what CONTRACT.md describes, in the
direction that lets a bypass through:

- **`INBOUND_SURFACE_DIRS` matched at any depth.** CONTRACT.md documents
  `src/server/`, `src/http/`, `src/api/`, `src/mcp/` — top-level directories —
  but the implementation exempted any path containing one of those names as a
  segment. `src/client/api/client.ts` was therefore silently exempt, which is
  the single most likely place a real client bypass would sit. Matching is now
  the documented top-level `src/<dir>/**` form. All four fleet files that
  motivated the exclusion are directly under `src/`, so nothing measured is
  given up.
- **The bare `<APP>_API_KEY` alias had been dropped from policing.** The seam
  resolves it, so a hand-read of it is the same defect; and the rule's claim to
  soundness is that it asks `clientTransportEnvKeys()` for the names it polices
  "rather than approximating them, so the rule and the seam cannot drift apart"
  — filtering that answer reintroduced exactly that drift, on the app's own
  canonical alias. The collision it dodged (a repo whose `RECORDINGS_API_KEY`
  holds an OpenAI key) is now handled by the waiver this rule already ships and
  echoes into the report, so one auditable line in one repo replaces a permanent
  silent hole in every repo.

`scripts/` staying in `SKIP_DIRS` is **kept**: it is not in the package's
`files`, so it is not shipped behaviour, and it is excluded for the same reason
tests already were. CONTRACT.md documents it.

#### Fixed: CONTRACT.md §3a promised `console.log` safety the runtime did not honour

Non-enumerability keeps the key out of `Object.keys`, spreads, and
`JSON.stringify`, but it does NOT hide an own property from an inspector: under
Bun — the declared engine — `console.log(resolution)` printed
`apiKey: "sk-..."` verbatim. A non-enumerable
`Symbol.for("nodejs.util.inspect.custom")` hook IS honoured by both
`console.log` and `Bun.inspect` (unlike `toJSON`, which this runtime never
invokes when non-enumerable), and adds nothing to `Object.keys` or to any
spread. The redacted form keeps `tier` and `source`, so a diagnostic dump stays
useful. §3a now states the two enforcement mechanisms separately rather than
implying one covers both.

## [0.8.4] - 2026-07-29

### BREAKING: the deployment-mode axis is removed; storage is a `sqlite | postgres` backend switch

Owner directive 2026-07-29. The three-way runtime placement
(`local | self_hosted | cloud`, plus the `remote` / `hybrid` / `self-hosted`
aliases) is gone from the whole contract surface — schema, types, validators,
manifests, templates, docs. This repo was originally scoped N/A by the
modes-simplify stream; that was wrong: it is the propagation source, and the
vendored kit template (`src/kit/templates/mode.ts`) copied the old normalizer
into every scaffolded repo.

- **A manifest carrying `deploymentMode(s)` now FAILS validation** — zod
  `.strict()` plus `additionalProperties: false` in both JSON-Schema copies —
  rather than the field being ignored. Both value spellings (`self_hosted`,
  `self-hosted`) are covered, and surface-level `deploymentModes` fails too.
  Omission now validates (the old schema *required* the field per surface);
  both directions are pinned red-first in `tests/no-deployment-modes.test.ts`.
- **`STORAGE_MODES` becomes `["sqlite", "postgres"]`** — the SERVER's internal
  storage, matching `STORAGE_ENGINES`. `postgresql` normalizes to `postgres`;
  every removed placement word throws a migration hint, never silently maps.
  `DEPRECATED_STORAGE_MODE_ALIASES`, `DEPLOYMENT_MODES`,
  `DEPRECATED_DEPLOYMENT_MODE_ALIASES`, `DeploymentModeSchema`, and the
  `DeploymentMode` type are deleted from the export surface.
- **The client seam is `sqlite | http`** and never opens PostgreSQL directly:
  `ClientTransportKind` is now `"sqlite" | "http"`, the fleet env-flip
  (URL+key, no mode env) infers `postgres`-over-HTTP, and
  `resolveStorageMode` defaults to `postgres` when a `DATABASE_URL` is present,
  else `sqlite`.
- **Waiver eligibility** drops the placement input; a postgres backend or a
  `hasna-saas` story still refuses storage waivers. saas repos must declare
  `storage.mode: "postgres"`.
- `createCloudPoolFromEnv` is renamed `createServerPoolFromEnv` in the vendored
  kit; regenerate kits to pick it up.
- Migration for consumers: delete `deploymentModes` from `hasna.contract.json`,
  set `storage.mode` to `sqlite` or `postgres`, and update
  `HASNA_<APP>_STORAGE_MODE` values (`local`→`sqlite`;
  `cloud`/`self_hosted`/`remote`/`hybrid`→`postgres` on servers, or drop the
  variable on clients and rely on URL+key). Do NOT bump `@hasna/contracts`
  inside an in-flight modes-removal PR; land the repo's own removal first.

Note: 0.8.3 exists as a release commit on main but was never published to npm
(the registry ends at 0.8.2); this release ships as 0.8.4 so one version string
never names two different contents.

## [0.8.3] - 2026-07-27

### `no-cloud-scan` stops scoring its own inlined declaration, without switching a detector off

SUPERSEDES the first attempt at this in the same unreleased version. That attempt
is documented below rather than deleted, because two of its measurements are the
reason this one is shaped the way it is — and because it was merged, so anyone
reading `git log` will meet it.

WHAT IT GOT RIGHT, and this version keeps: key the mask on the array's VALUE
rather than on the identifier it is assigned to, because a bundler rewrites the
name and cannot rewrite the value. Measured there over 1656 build-output files in
41 consumer repos. Require `=` immediately before the literal so it is a value
being STORED, and withdraw the mask when `.`, `(` or `[` follows the closing
bracket, because that turns the array into a load. All three survive here.

WHY IT WAS NOT ENOUGH, measured apples-to-apples — its own bundle, scanned by its
own scanner: **six findings still standing**, `verdict: failed`, `EXIT=1`.

- **It matched one of the two shapes this package inlines.** The denylist array is
  the smaller half. `RUNTIME_PATTERNS` is a row per pattern —
  `{ pattern: "…", kind: "…", message: "…" }` — and it carries ALL EIGHT patterns,
  including both credential env keys and the legacy config dotdir. Masking the
  array cleared nothing that the rows did not put back.
- **Two forbidden names were spelled at finding SITES, in code rather than data.**
  `pattern === ".hasna/cloud"` and `path.includes(".hasna/cloud")` are not
  literals a structural rule can attribute to anything, and a bundler inlined them
  into every consumer just the same. They are read off the pattern table now, and
  a test asserts no forbidden name appears in `src/no-cloud.ts` outside it.
- **It was scoped by PATH**, needing `GENERATED_OUTPUT_DIRS`, then
  `AUTHORED_SOURCE_DIRS` to stop `src/dist/loader.ts` claiming the exemption,
  then an ordering rule between the two. Attribution reads content, so none of
  that apparatus exists here and `git mv` cannot change a verdict.
- **It left the identity-keyed exemption in place** — see below, that one is a
  live credential blind spot rather than a false positive.

### `no-cloud-scan` stops scoring its own inlined declaration, without switching a detector off

A repo that bundles `@hasna/contracts` without externalising it gets this
scanner's own pattern declaration copied into its build output. The scanner read
that copy back and scored it as the consumer's breach — measured against
published 0.8.1 and 0.8.2 on a consumer whose only import is
`scanNoCloudTarget`: **six findings in one `dist/index.js`**, none of them
removable by the consumer, with `open-cloud` reported against a repo that never
used it.

**A live credential blind spot is removed at the same time.** 0.8.1 and 0.8.2
exempted a file by PATH plus package identity plus two "marker" substrings, and
the exemption returned early for the whole file — which took the three `config`
patterns with it, and those have no import to look for, so a bare occurrence is
their only detector. Measured on the published bytes of both versions with a
byte-identical `dist/no-cloud.js` carrying a planted shared-RDS credential:
named `@hasna/contracts` it PASSED with zero findings; named anything else the
same bytes scored two criticals. The one artifact whose credential detectors
were off was this package's own release. That mechanism is gone.

Two approaches were rejected on measurement before this one landed:

- **Exempting build-output directories.** A `dist`-only tarball leaking the
  shared RDS credential scored two criticals before and zero after. A
  false-positive fix that opens a credential blind spot is worse than the bug.
- **Treating a bare mention with no import specifier as a false positive.**
  Unsound in both directions. `bun build --external` compiles `require("x")` to
  `__require("x")` — a real load carrying no specifier the matcher could see —
  and a source file importing its own `package.json` as JSON makes the bundler
  inline the whole manifest, so a dependency name sits in the artifact with zero
  specifiers anywhere in the file. Both are true positives.

What is actually different about the copied declaration is that the text IS this
scanner's own constant, still in the inert data shape it was written in. That is
what is matched, and only the characters it spans are dropped:

- the array must equal the denylist element for element, so a subset, a superset
  and a reordering are all somebody else's data;
- a row must equal one table row ENTRY FOR ENTRY — same entry count, every value
  equal — so a forbidden name cannot be paired with a message that is not its own,
  and no extra field can ride along inside the span. Matching three named keys and
  a bounded key set were both tried first and each left one free slot. The rule is
  complete only together with its other half: the parser REFUSES a record that
  repeats a key, because `Map` keeps the last value and a shadowed one would sit
  inside the blanked span having been compared to nothing;
- the collection must sit where data sits, must not be indexed, called or
  member-accessed in place, and if it is bound to a name, no load call in the
  file may name that name. `__require(DENY[0])` is a real load whose specifier
  never appears in specifier position, and that is what these three close.

**No detector is switched off anywhere.** Each occurrence is judged on its own,
so the same file keeps every check for every other occurrence in it: a consumer
that bundles this package AND reads the retired runtime's config, or loads it, is
still reported. No path and no package identity is consulted, so `git mv` cannot
change a verdict, and a `package.json` is still read whole because attribution is
restricted to C-family source — the only thing a bundler inlines a JavaScript
constant into.

Also in this release:

- **Every forbidden name is spelled exactly once, in the pattern table.** Two
  finding sites re-spelled the legacy config dotdir. Those copies were CODE
  rather than data, so nothing structural could ever attribute them, and a
  bundler inlined them into every consumer just the same. A test now asserts no
  forbidden name appears in `src/no-cloud.ts` outside the table.
- **`importsModule` and `importedBindings` recognise the bundler's require
  wrapper.** A word boundary does not exist inside `__require`, so the one form
  build output actually uses was invisible to both. Widening a load matcher can
  only ADD findings: a load it fails to recognise falls through to reporting the
  bare name, so a name recognised here is reclassified, never cleared.
- **`scripts/mutation-audit.ts`**: 17 new mutations (M71-M87) pinning each rule
  above in both directions, plus repairs to TEN stale anchors — seven of which
  were already stale on `main`, so those rules had been unverified since the last
  refactor and the audit could not come back clean. The script now writes the
  in-flight mutation to a gitignored sentinel and repairs an abandoned one on the
  next run (it had committed `if (false) roots.push(...)` into this repo),
  handles signals, strips ANSI before parsing counts, refuses a zero-pass
  baseline as "no reading" rather than "green", passes an explicit suite timeout
  so machine load cannot manufacture a red baseline, and accepts `--anchors` to
  check staleness without running the suite.

<!-- superseded, retained for the record: the first 0.8.3 attempt -->

### `no-cloud-scan` stops reporting its own denylist as the consumer's breach

`FORBIDDEN_SHARED_CLOUD_RUNTIMES` is a pair of string literals, so any repo that
bundles `@hasna/contracts` without externalising it gets
`["@hasna/cloud", "open-cloud"]` **inlined into its build output**. The scanner
read its own denylist back out of the consumer's artifact and scored it as the
consumer's breach — permanently, with nothing the consumer could remove to fix
it. The tell was `open-cloud` reported against repos that never used it.

- **The exemption is keyed on the array's VALUE, not on a variable name.** An
  earlier spelling matched the identifier `FORBIDDEN_SHARED_CLOUD_RUNTIMES`
  preceded by `const`/`let`/`var`, and that recognised almost nothing a bundler
  emits: bun's lazy `__esm` wrapper hoists the declaration and emits a bare
  assignment with no keyword, and `--minify-identifiers` renames the variable and
  folds it into a comma sequence with no trailing `;`. Both real shapes are now
  pinned as tests. Measured across 1656 build-output files in 41 consumer repos:
  18 of 18 files whose only hits were the two module names are cleared; the other
  4 are `registerCloudTools`/`registerCloudCommands` in a repo that defines its
  own, which is a `symbol` pattern and was never a bare-mention finding.
- **The exemption applies to build output only, so no repo can exempt itself.**
  An authored `src/loader.ts` that writes the same array and then loads through
  it — `await import(NAMES[0])` — is unchanged and still fails, as is the same
  file inside a packed tarball. A folder named `dist` **under** `src/` is
  authored, not output; authored-looking structure under build output
  (`dist/src/index.js`, which `tsc --rootDir .` emits) is still output.
- **Only the inlined literal is blanked, in place, with same-length spaces.** A
  second mention on the same minified line, a real `require("@hasna/cloud")`
  beside it, an externalised `import … from "@hasna/cloud"`, runtime config such
  as `HASNA_CLOUD_*`, a shorter or reordered or longer array, a TOML array under
  `dist/`, and any array the code then invokes on
  (`[…].map((n) => require(n))`, `[…][0]`) all remain findings. `package.json`
  and `bun.lock` edge checks are untouched, so a real install edge still fails
  the gate regardless of what the bundle looks like.
- Every clause above is pinned: 11 of 11 mutations to the new code are caught by
  `tests/cli.test.ts`, each one verified to have changed the bytes on disk.

## [0.8.2] - 2026-07-27

### `no-cloud-scan` closes three blind spots that 0.8.1 opened

0.8.1 went quiet on references the substring scanner it replaced had caught.
Fourteen fixtures in an 81-fixture review corpus flip from `exit 0` to `exit 1`
here, and none flips the other way. Each of the three causes below was
demonstrated on a running fixture, and every fix is pinned by a test that fails
on 0.8.1.

Not all fourteen are *executable loads*, and the distinction is recorded rather
than smoothed over: some are package resolution without execution, one is a
capability withdrawal on a shape that does no package resolution at all, and two
are lockfile text naming the package outside any edge the graph walk can read.
One — a regex misread as a comment — was confirmed a true positive by executing
a planted stub, so 0.8.1's `exit 0` there was a genuine miss.

- **The guard-test allowlist suppressed real access to the package.** The
  withdrawal test recognised `import(` and `require(`; any other way of reaching
  the package was scored as a mention and erased, against a clean scan. What each
  shape does differs, and the difference matters:
  `createRequire(import.meta.url)("…")` loads and executes;
  `Bun.resolveSync` and `require.resolve` perform package resolution and return a
  path without executing (and throw when the package is absent, so either way
  they are a working presence probe); `new Worker(new URL("…", import.meta.url))`
  does *not* do package resolution at all — measured, it resolves relative to the
  importing file. The exemption was also claimed by FILENAME at any depth — from
  `dist/`, from the repo root, from `config/` — so shipped build output could
  carry the suppressed name. Now: the path is anchored to exactly
  `src/no-cloud-boundary.test.<ext>`, and the exemption survives only if the file
  cannot resolve a module at all and every literal mention sits in a position on
  an ALLOWLIST of inert ones. An unrecognised callee withdraws it, so the next
  spelling fails closed rather than through. The rule is deliberately a
  CAPABILITY check — "a file that only asserts absence should not be able to
  reach modules" — which is weaker and more defensible than "this shape loads the
  package".
- **Comment masking blanked live code and did not notice.** After `)` the masker
  read a `/` as division, but in JS `if (s) /a[//]b/` opens a REGEX — so the
  lexer walked into the regex body, took the `//` inside the character class for
  a line comment, and blanked the rest of the line including a live `require()`
  of the retired runtime. Because the masker believed it had succeeded, the
  fail-open guarantee never fired. Now the provenance of the `(` decides: a
  control head is followed by statement position where `/` opens a regex, a call
  or grouping by operator position where it is division. The two cases that
  remain undecidable — an unbalanced `)`, and a call whose slash could swallow a
  comment opener — discard the whole mask and fall back to raw text.
- **`bun.lock` module patterns lost their text fallback.** When the graph walk
  took over `bun.lock`, config patterns kept a text scan and module names did
  not. A nested npm `overrides` pin and a path-keyed yarn `resolutions` pin both
  name the package in plain text and both scanned clean. Now `overrides` and
  `resolutions` are read recursively and path keys are split (ranges and globs
  included, never at the scope sigil), and any module name the lockfile spells
  out that the walk neither reported nor actively cleared is reported. The
  fallback is bounded to a lockfile token, so `@hasna/cloudflare-adapter` and
  `../open-cloud-shim` stay clean.
- **Unchanged, deliberately:** a transitive `file:`/`link:` resolution in a
  single-workspace lockfile still reports nothing. That was probed on bun 1.3.14
  — the package lands nowhere on disk and `require()` of it fails — and it is
  what clears `hasna/logs`. `lockfileWalk` now returns the names it cleared that
  way so the new text fallback can stay quiet about exactly those and nothing
  else.
- **Scope of a `passed` verdict, now asserted rather than assumed.** The scan
  reads an allowlist of directories and extensions, so `passed` does not mean "no
  reference anywhere". Paths with no source-directory segment (`app/api/…`),
  `tests/` and `test/`, an on-disk `node_modules` copy with no manifest entry,
  `Dockerfile`/`.tf`/extensionless `bin` scripts, assembled (`"@hasna/" +
  "cloud"`) and escaped (`"\x40hasna/cloud"`) specifiers, and a `git+ssh:`
  dependency installing under the package name are all out of scope. Each is
  pinned by a test so closing one cannot happen silently.
- Schemas, verdict vocabulary and exit-code semantics are unchanged. Repos whose
  `bun.lock` names a forbidden runtime outside any edge the walk can read, and
  repos whose guard test lives outside `src/`, will newly report `failed`.

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
