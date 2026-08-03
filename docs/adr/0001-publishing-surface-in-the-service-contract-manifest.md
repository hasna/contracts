# 1. A `publishing` surface in the service contract manifest

- **Status:** accepted
- **Date:** 2026-08-03
- **Applies to:** `hasna.service_contract.v1` (`hasna.contract.json`)

> This is the first architecture decision record in this repository, so it
> establishes the convention: `docs/adr/NNNN-<slug>.md`, zero-padded to four
> digits, numbered in the order decisions are accepted, never renumbered. Each
> record is immutable once accepted; a later decision that changes this one
> gets its own number and this file's status becomes `superseded by NNNN`.

## Context

### The forcing function is external and dated

npm is deprecating granular access tokens that bypass 2FA (GitHub changelog,
2026-07-08). In phase 2, around January 2027, those tokens lose the ability to
publish directly: afterwards they can read and stage, and nothing else. The
supported paths forward are trusted publishing, where a CI job exchanges
workload identity (OIDC) for a short-lived publish credential, and staged
publishing, where an upload is promoted in a separate step.

This is not a preference we can defer. On the day it lands, every package whose
release depends on a long-lived token stops being publishable by its current
route.

### What the fleet actually does today

Measured across all 212 Hasna npm packages (`@hasna` 174, `@hasnaxyz` 31,
`@hasnatools` 4, `@hasnafamily` 2, `@hasnastudio` 1):

| state | packages |
| --- | --- |
| detected as publishing from CI | 34 |
| not detected as publishing from CI | 174 |
| undetermined | 4 |

Among the 26 repos that do publish from CI there are exactly **six** distinct
(workflow file, environment) pairs:

| workflow file | environment | repos |
| --- | --- | --- |
| `rust-release.yml` | *(none)* | 9 |
| `publish.yml` | *(none)* | 9 |
| `publish-package.yml` | `publish` | 8 |
| `release.yml` | *(none)* | 5 |
| `publish.yml` | `release` | 2 |
| `publish-package.yml` | *(none)* | 1 |

The packages this fleet ships *daily* — todos, conversations, instructions,
knowledge, accounts, projects, secrets, loops, emails — are hand-published from
a workstation with no CI release workflow at all. So roughly 140 packages need
a CI release path built before January.

### The gap in the contract

The manifest models what a package **exposes** and says nothing about how it
**ships**. Grepping `src/hasna.contract.schema.json` for `publish`, `release`,
`workflow`, `npm`, `registry`, `repository`, `provenance`, `attest` and
`trusted` returns zero hits each, against a positive control of one for
`serviceSurfaces`.

Without a declared source of truth, registering ~140 trusted publishers means
hand-maintaining the same mapping across ~140 repositories, with no validation
and no way to ask the fleet a question about its own release posture.

### The measurement that shaped the design

The survey that produced the table above detected publishers by walking
`jobs.*.steps[].run` for a publish verb. `hasna/accounts` publishes via
`bun run scripts/release-provenance.ts publish-staged` — a bespoke script — so
it is recorded as having **no publish job**, while in fact running the most
advanced pipeline we own: staged publish, provenance, `ensure-unpublished`,
signature verification, `id-token: write`, environment `npm-release`.

Two conclusions follow, and both are load-bearing:

1. `npm publish` in a run-step is not the only publish mechanism. The 34 is a
   floor, not a total.
2. **A schema that assumes a single mechanism would be wrong on the best
   example we own.** Any model whose categories are derived from what a
   detector can see inherits the detector's blind spot.

## Options considered

### Option A — name it `release`

Rejected. `hasna.release.v1` already exists in this repository as a publish
*receipt*: `appId`, `package`, `version`, `gitSha`, `publishedAt`,
`evidenceRefs`. It records that a specific version was published at a specific
time.

What this decision needs is the opposite kind of statement — a standing
declaration of how the repo ships, true before any publish happens and
unchanged by one. Naming both "release" would put a record of an event and a
declaration of policy under one word in the same contract, in a repository
whose central discipline is that separate axes get separate names.

### Option B — a single flat `mechanism` enum

Rejected. The obvious shape is one enum along the lines of
`ci-workflow | manual | staged | none`. It fails on the accounts case: that
pipeline is CI **and** trusted-publisher **and** staged **and**
provenance-bearing, and a single value can carry at most one of those four.

The properties are genuinely independent. A token-authenticated CI publish and
an OIDC-authenticated one differ on credential but not mechanism; a staged
publish can be either. Collapsing them loses exactly the distinctions the npm
migration turns on — which package is safe in January and which is not.

### Option C — put it under `metadata`

Rejected. `metadata` is `additionalProperties: true`, so this would need no
schema change at all and would validate immediately. That is precisely the
problem: no validation, no conformance, no shared vocabulary. `metadata` is
where waivers and escape hatches live; a field that ~140 repos must fill in
correctly, and that automation will read to register credentials, belongs in
the validated surface.

### Option D — derive it by scanning each repo's workflows

Rejected. That is the detector that produced the accounts false negative. A
derived answer is only as good as the generator's axes, it is silently wrong
rather than absent when it misses, and it cannot express intent — a repo that
*should* publish with provenance and currently does not is indistinguishable
from one that never will.

Declaration and detection are complements, not substitutes: the manifest states
intent, and a scanner may later check reality against it. The scanner cannot be
the source of truth.

### Option E — an `unknown` status

Rejected. `unknown` was tempting because the survey has 33 `unknown` and 13
`repo-unreachable` rows. But those are properties of the *survey*, not of the
repo: a repo always knows how it ships. Adding `unknown` would let a manifest
launder a surveyor's uncertainty into the contract.

Absence already carries that meaning, because the property is optional — which
is what makes `unpublished` worth having as an explicit value.

## Decision

Add an **optional, additive** top-level `publishing` property to
`hasna.service_contract.v1`.

```jsonc
"publishing": {
  "status": "published",              // published | unpublished
  "targets": [
    {
      "package": "@hasna/accounts",   // registry name, incl. scope
      "registry": "registry.npmjs.org", // bare host; no scheme, no credentials
      "access": "public",             // public | restricted        (optional)
      "mechanism": "ci",              // ci | manual
      "credential": "trusted-publisher", // trusted-publisher | token
      "flow": "staged",               // direct | staged      (default direct)
      "provenance": "required",       // required | best-effort | none
      "workflow": {                   // required iff mechanism = ci
        "provider": "github-actions", // github-actions | gitlab-ci
        "repository": "hasna/accounts",
        "file": "release.yml",        // bare filename, not a path
        "environment": "npm-release"  // optional; absent = no gate
      }
    }
  ]
}
```

The shape follows from the context above:

- **Four orthogonal axes** (`mechanism`, `credential`, `flow`, `provenance`)
  rather than one enum, so the accounts pipeline survives without losing three
  of its four properties.
- **`manual` is a first-class value.** It is the fleet's dominant state; a
  vocabulary that could not express it would push ~140 repos into either
  omitting the property or misdeclaring themselves.
- **`targets` is an array**, mirroring `serviceSurfaces`, because a repo may
  ship several packages or reach several registries. `package` is carried
  explicitly because it is *not* derivable from `name`: the short app name and
  the published package name differ, and the scope varies across five scopes.
- **The registry is declared, never assumed.** `registry` is a bare
  `host[:port][/path]`; a scheme is refused, which makes userinfo structurally
  impossible and so a public manifest cannot carry a credential in this field.
- **`workflow` is exactly the registration triple** a registry consumes
  (`--repo`, `--file`, `--env`). `file` is a bare filename because that is what
  the registration is keyed on, and `environment` is optional because 15 of the
  26 CI publishers have none — its absence means *no environment gate*, not
  *unknown*.
- **The CI provider is declared** rather than hardcoded to GitHub Actions, for
  the same reason the registry is: npm's trusted publishing already supports
  more than one provider.

Invariants enforced at validation, each refusing a state that cannot exist:

| invariant | why |
| --- | --- |
| `status: published` requires ≥ 1 target | a publish with no destination is not a declaration |
| `status: unpublished` forbids targets | otherwise two fields disagree |
| `mechanism: ci` requires `workflow` | the registration needs the triple |
| `mechanism: manual` forbids `workflow` | a workflow implies CI |
| `credential: trusted-publisher` requires `mechanism: ci` | workload identity is not issuable to an interactive publish |
| duplicate `package`+`registry` refused | two rows would silently disagree |

The property is **not** added to `required`, and no repo class constrains it:
publishing is orthogonal to `library | cli-with-store | service | saas`.

## Consequences

### Immediate

- Every existing manifest keeps validating unchanged. Verified rather than
  asserted: across 129 real manifests (80 fetched from the default branches of
  the `hasna` and `hasnaxyz` orgs, 49 on-disk checkouts) the validator's output
  is **byte-identical** before and after — same passes, same failures, same
  issue paths and codes (sha256 `8316b514…` and `9b31ab6a…` respectively).
  Neither run produces a `publishing`-related issue.
- The change touches three copies of the schema that must move together: the
  Zod schema in `src/schemas.ts`, which is the runtime gate; the exported
  `SERVICE_CONTRACT_JSON_SCHEMA` in `src/service-contract.ts`; and the shipped
  `src/hasna.contract.schema.json`, which a test asserts is equal to the
  exported constant.

### What this deliberately does not do

- It does not populate any manifest. Filling in ~140 repos is a separate
  migration, and this record does not prejudge its ordering.
- It does not change any npm setting, register any trusted publisher, or
  publish anything.
- It does not add a conformance requirement. Making `publishing` mandatory, or
  gating releases on it, would break every repo the moment it landed; that is a
  later decision to be taken once the surface is populated.

### Costs and risks accepted

- **A declaration can drift from reality.** Nothing yet checks that a declared
  workflow file exists or that a declared trusted publisher is registered. The
  mitigation is a future conformance check comparing declaration against the
  repo and the registry — deliberately not bundled here, because the surface
  has to exist and be populated before a gate over it can be anything but a
  fleet-wide failure.
- **Per-target divergence is expressible; per-package release *policy* beyond
  these axes is not.** A repo needing, say, different provenance per package
  can already declare separate targets, but a genuinely new axis is a v2
  concern.
- **The vocabularies are closed.** A new CI provider or a new credential kind
  needs a schema change. This is the same trade the rest of this contract makes
  and it is the reason the fields validate at all.
- **`file` as a bare filename** would need revisiting if a provider ever keys
  registrations on a path.

## Evidence

- Survey: `2026-08-02-npm-trusted-publisher-mapping.tsv`, 212 rows.
- npm token deprecation: GitHub changelog, 2026-07-08.
- Gates on this change: `bun run typecheck` and `bun test` run separately, plus
  `bun run conformance` and `bun run src/cli/index.ts repo-conformance .`.
