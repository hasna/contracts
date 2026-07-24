# Factory v1 Contract Inventory and Minimal Specification

## Provenance

- preserved input handoff: `550` lines, SHA-256 `1f2904561677b1082a3193f59b25a6ed1faf99d4dcded8521943a526e1685470`
- inherited intermediate source: `555` lines, SHA-256 `fb34c7dd419bf2c21a5c0dc70cc02e581b92f52fb11ec683ff2aad7b4492f03d`
- current remediation input: `270` lines, SHA-256 `73c714646ddc3967b9593b32bb7e6ff629974bc9a08cb2cbf83b698e0327e084`

## Purpose and scope

This file is a **docs-only IAP9-00049 inventory pass** for `hasna/contracts`.
It is an evidence-bound update only: it does not add schemas, serializers, fixtures,
adapters, tests, or releases in this repository.

Current working base:

- canonical checkout: `/home/hasna/workspace/hasna/opensource/open-contracts`
- canonical worktree root: `/home/hasna/.hasna/repos/worktrees/open-contracts`
- current contracts main target: `6238e96476b26b950d0a20295f330bf6c0977e90`

## Canonical source references

ADR 0002 is directly inspectable and included in this remediation:

- Factory PR 7 (merged): `https://github.com/hasnaxyz/iapp-factory/pull/7`
- merge commit: `3846dc4d3e30dbef4ee50dc1983a712de8d2d531`
- reviewed head: `9a01f66293527a13fff724f663edf989b13dbcf3`
- check command used for direct proof:
  `git -C /home/hasna/workspace/hasnaxyz/internalapp/iapp-factory show 3846dc4d3e30dbef4ee50dc1983a712de8d2d531:docs/architecture/adr-0002-production-internal-iapp.md`

This review is for the merged Factory PR 7.
This is treated as the controlling architecture reference for the current document.

## External effect kinds (exactly fifteen)

The merged architecture defines these **exactly fifteen** externally addressable effect kinds.

| Effect kind | Meaning |
| --- | --- |
| `todos.claim` | Lock and move the task record to in-progress. |
| `todos.unclaim` | Release task lock without terminal disposition. |
| `todos.complete` | Mark terminal disposition and persist completion outcome. |
| `todos.park` | Place task in blocked/needs-human disposition without deleting intent. |
| `conversations.post` | Emit update/event to the **canonical pre-provisioned project channel**. |
| `dispatch.enqueue` | Queue cross-surface work units for downstream processing. |
| `model.infer` | Request model execution and capture brokered result. |
| `evidence.put` | Persist evidence references and receipts. |
| `quarantine.put` | Isolate mutable material during failure or repair with ticketed retention. |
| `quarantine.expire` | Delete quarantine content by exact ticket/version tuple (exact delete boundary). |
| `checkpoint.anchor` | Persist durable recovery anchor for one closed-head transition boundary. |
| `checkpoint.restore_materialize` | Materialize a checkpointed head in a bounded fresh workspace. |
| `git.publish` | Persist and publish candidate via staged git/provider transition sequence. |
| `webhook.deliver` | Deliver notifications using explicit signed webhook envelope. |
| `worktree.cleanup` | Reclaim temporary worktree after terminalization. |

## `git.publish` stages (exactly eight)

Each stage maps to one bounded identity and one bounded privilege set.

| Stage | Meaning |
| --- | --- |
| `worktree_prepare` | create and bind the exact assigned worktree snapshot. |
| `candidate_commit` | persist candidate commit and candidate descriptor. |
| `branch_handoff` | no-remote handoff of the exact local branch/head/candidate. |
| `push` | protected, non-force push of the exact committed head. |
| `pr_open` | open a PR only; does not mutate provider checks. |
| `pr_update` | update the exact authorized PR only; does not mutate provider checks. |
| `provider_readback` | read provider view for handoff/branch/PR truth alignment. |
| `merge_readback` | read-only merge outcome verification; no merge mutation and no merge stage exists. |

No merge mutation stage is defined by this architecture.

`worktree.cleanup` applies only to the exact assigned temporary worktree.

## Live provider evidence snapshot

Fact table from provider evidence refreshed live by the coordinator on **2026-07-24**.

| PR | State | Head SHA | Merge/Current SHA | Hosted verify |
| --- | --- | --- | --- | --- |
| 14 | CLOSED (unmerged) | `16cbc91a40579cb1acfab5407e50b4d71e5989ac` | no merge commit | n/a |
| 18 | MERGED | `79e8bf352c22885d25222e6f85506a506b15c66b` | `561940d7fb5f2be4993a667f5de4054a44e03822` | FAILURE |
| 19 | MERGED | `d161b0e9ee5ecac4a26929c846da2a8caa545641` | `05c99537a3d465b8cd4434c3ffb69e96a69c22ea` | SUCCESS |
| 21 | MERGED | `fb58f19e69567e17e29d2de10fdaee8f71f2f234` | `c76d531555bfd945cf252bd724b18614b82aaad6` | SUCCESS |
| 22 | MERGED | `56858c1b127a8bc0db139a0b5af44982d690f3c2` | `6238e96476b26b950d0a20295f330bf6c0977e90` | FAILURE |

Interpretation:

- PR 14 is closed and unmerged with no merge commit.
- PR 18 and PR 22 are merged with hosted verification failure.
- PR 19 and PR 21 are merged with hosted verification success.
- Current main (`6238e96476b26b950d0a20295f330bf6c0977e90`) remains unhealthy because PR 22 hosted verification fails.

## Task graph and direct/transitive dependency boundaries

This section preserves the exact existing node identities, statuses, and dependency gates.

Arrow form on one code line (main chain only):

`39377614-b24a-4b7b-adc1-a777da83718f` (in_progress) -> `43bbb6e2-80ea-4a40-a8f9-3ab10029ef66` (pending) -> `63823e5d-7fa5-4089-9db8-8a57318bfe5f` (pending) -> `b6c0e528-8989-4dd0-9ec0-dbde114fb72f` (pending) -> `a64c37fa-80af-404e-91d5-17dd1225d1d7` (pending) -> `a24336ab-e8f5-4f5c-a504-70cf1bf683bd` (pending)

In exact text:

- additional gate arrow: `c626b523-737c-4b6e-a26d-a39563346c1f` -> `63823e5d-7fa5-4089-9db8-8a57318bfe5f` and `a64c37fa-80af-404e-91d5-17dd1225d1d7`
- additional gate arrow: `55734b19-e3eb-49e5-a850-7d98aef25a8e` -> `a24336ab-e8f5-4f5c-a504-70cf1bf683bd`
- `IAP9-00049` directly depends on completed `IAP9-00048`.
- `IAP9-00041` direct dependencies are exactly: `IAP9-00049` / `0a1182f2-5782-4606-a30d-38d44391faaa`, `55734b19-e3eb-49e5-a850-7d98aef25a8e`, `b6c0e528-8989-4dd0-9ec0-dbde114fb72f`, `a64c37fa-80af-404e-91d5-17dd1225d1d7`, `a24336ab-e8f5-4f5c-a504-70cf1bf683bd`.
- For `IAP9-00041`, `39377614-b24a-4b7b-adc1-a777da83718f`, `43bbb6e2-80ea-4a40-a8f9-3ab10029ef66`, `63823e5d-7fa5-4089-9db8-8a57318bfe5f`, and `c626b523-737c-4b6e-a26d-a39563346c1f` are transitive-only.

## Current implemented schema inventory and source alignment

`@hasna/contracts` package version at this base is `0.7.0` (`CONTRACTS_PACKAGE_VERSION`).
Provider merge/version evidence is not itself release authority, and this is an
evidence-only baseline. None of the nine provisional schema names, fields, or
mappings is canonical for Factory adoption until the complete task chain is
terminal and one exact green release artifact/digest is pinned.

Observed factory-side implemented mappings (from merged Factory `src/core/contracts.ts`) and contracts-side availability (from local `src/schemas.ts`):

| Schema | Role (as implemented / sourced) | Factory consume state |
| --- | --- | --- |
| `hasna.work_run.v1` | generic run projection | implemented and reused via `CONTRACT_SCHEMAS.workRun` |
| `hasna.evidence_ref.v1` | evidence reference (`kind/uri/redaction` projection) | implemented and reused via `CONTRACT_SCHEMAS.evidenceRef` |
| `hasna.decision_envelope.v1` | backend selection / model routing decision | implemented and reused via `CONTRACT_SCHEMAS.decisionEnvelope` |
| `hasna.capability_card.v1` | backend capability advertisement | implemented and reused via `CONTRACT_SCHEMAS.capabilityCard` |
| `hasna.validation_plan.v1` | verify plan / check execution manifest | implemented and reused via `CONTRACT_SCHEMAS.validationPlan` |
| `hasna.service_contract.v1` | service manifest and conformance envelope | implemented and reused via `CONTRACT_SCHEMAS.serviceContract` |
| `hasna.project_panel.v1` | project status/health projection | implemented and reused via `CONTRACT_SCHEMAS.projectPanel` |
| `hasna.cost_estimate.v1` | internal estimate projection | implemented and reused via `CONTRACT_SCHEMAS.costEstimate` |
| `hasna.context_pack.v1` | bounded handoff bundle | implemented and reused via `CONTRACT_SCHEMAS.contextPack` |
| `hasna.task_to_pr_projection.v1` | work-run-to-PR projection | implemented on current Contracts main, but **not consumed by Factory `CONTRACT_SCHEMAS`**; adoption remains provisional pending nonterminal disposition and release-chain closure |

## Restored current gap inventory (contractual debt to close)

From merged Factory evidence and local source review:

- `RunRecord` collapses logical run and attempt in a single model; there is no canonical explicit `attempt` generation state.
- No canonical generation/authority/fence object is contract-bound in persisted run model.
- stage evidence is not yet hash-chained with a monotonic predecessor chain guarantee.
- errors remain free-text/partial and can miss canonical category/typed retryability semantics.
- operation semantics may drift by face because transport behavior is not fully normalized.
- list/page/stream size and bound limits are not yet contract-guaranteed.
- evidence refs do not yet prove complete gate closure by themselves.
- verifier, publisher, migration, and cleanup paths do not all share one exact-subject attestation chain.

Current fail-open debt from merged Factory evidence is kept as diagnostics only:

- HTTP health/ready are ad hoc and not strict contract envelopes.
- missing Contracts CLI returns `skipped` in validation path as success.
- repo conformance can skip and still pass as success.
- best-effort logging can ignore validation errors while continuing downstream flow.

Authoritative boundaries that must fail closed for future implementation (not diagnostics):

- attempt identity and status boundaries must be bounded and immutable once terminal.
- generation/authority/fence drift must fail closed.
- evidence completeness and attestations must be checked before terminal claims.
- provider readback and merge outcome treatment must be exact and deterministic.

## Proposed Factory schemas (exactly nine, provisional)

These nine proposals are preserved and strengthened to reinforce subject binding,
monotonicity, boundedness, redaction policy, immutability, mode scoping, and cross-face consistency.

### 1) `hasna.factory_run.v1`

Required fields:
`schema`, `id`, `createdAt`, `updatedAt?`, `traceId`, `taskRef`, `projectRef`,
`repositoryRef`, `objectiveDigest`, `scopeDigest`, `verificationPolicyDigest`,
`baseBranch`, `baseSha`, `operationRegistryVersion`, `idempotencyKey`,
`status`, `latestAttemptRef`, `attemptCount`, `predecessorRunRef?`.

Invariants:

- identity fields are immutable after creation.
- `idempotencyKey` is deterministic from task, normalized objective, repository,
  base branch, baseSha, scope, verification policy, and operation-registry
  version only.
- `status` is terminal-only-in-monotonic order and includes terminal values (`succeeded`, `failed`, `cancelled`, `blocked`).
- `latestAttemptRef` references the latest attempt under the same run and must be
  status-consistent; it may be terminal only when the run is terminal.
- predecessor run linkage is allowed only across exact base or objective boundary changes and is immutable once set.
- subject binding must include repository/project/task and run authority and be unchanged except terminal closure.

### 2) `hasna.factory_attempt.v1`

Required fields:
`schema`, `id`, `runRef`, `attemptNumber`, `generation`, `createdAt`, `startedAt?`,
`finishedAt?`, `backendCapabilityRef`, `profileRef?`, `worktreeRef`, `branchRef`,
`status`, `stage`, `repairCycle`, `outcome?`, `errorRef?`, `predecessorAttemptRef?`.

Invariants:

- uniqueness constraints on `(runRef, attemptNumber)` and `(runRef, generation)`.
- attempt states progress monotonically and never regress.
- `terminal` states are append-only immutable and cannot be rewritten.
- repair increments `repairCycle` only through a fresh attempt.
- `outcome` and `errorRef` may only appear on terminal statuses.
- cross-face identity must be identical for CLI/MCP/SDK/HTTP.

### 3) `hasna.factory_fence.v1`

Required fields:
`schema`, `runRef`, `attemptRef`, `generation`, `authorityEpoch`, `leaseDigest`,
`issuedAt`, `expiresAt`, `status`, `supersededByGeneration?`.

Invariants:

- raw lease token is forbidden.
- only non-expired, non-superseded fence with matching authority epoch permits mutations.
- `generation` is per `(runRef, attemptRef)` and must be monotonic non-decreasing.
- `authorityEpoch` is monotonic per run/attempt and strictly increases on authority transitions.
- exact fence subject binding requires immutable `(runRef, attemptRef)`.
- mutation or cancellation must create a superseding fence row, never update-place.

### 4) `hasna.factory_event.v1`

Required fields:
`schema`, `id`, `runRef`, `attemptRef`, `generation`, `sequence`, `eventType`,
`actorRef`, `createdAt`, `payload`, `payloadDigest`, `previousEventDigest?`, `redaction`, `traceId`.

Invariants:

- `(runRef, sequence)` is strictly monotonic and bounded.
- immutable append-only event stream; update/delete is forbidden.
- `previousEventDigest` must bind to prior event digest for non-initial entries.
- payloads are bounded in byte size and free of raw credentials, raw leases, raw file system paths, raw transcripts, or secrets.
- event type set is closed and versioned.

Closed event types for this scope:
`run.admitted`, `attempt.started`, `stage.started`, `stage.completed`, `backend.classified`, `lease.renewed`, `cancel.requested`, `attempt.terminal`, `verification.attested`, `publication.attested`, `worktree.preserved`, `worktree.cleaned`, `migration.attested`.

### 5) `hasna.factory_error.v1`

Required fields:
`schema`, `code`, `category`, `retryability`, `message`, `stage?`,
`backendRef?`, `profileRef?`, `causeRef?`, `details?`, `redaction`.

Invariants:

- `category` is a closed enum:
  `validation`, `authorization`, `dependency_block`, `claim_conflict`,
  `admission_limit`, `timeout`, `usage_limit`, `authentication`,
  `backend_unavailable`, `scope`, `verification`, `secrets`, `publication`,
  `cancellation`, `lease_lost`, `authority_mismatch`, `migration`, `internal`.
- `code` is closed and maps to the `category` and face-specific contract behavior.
- `retryability` is one of `never`, `same_attempt`, `new_attempt`, `after_external_change`.
- message is summary-only; detailed sensitive context belongs to redacted evidence references.
- credentials, tokens, raw transcript blobs, raw paths, and secret-bearing values are forbidden.
- retryability is explicit and immutable for terminalized attempts.

### 6) `hasna.factory_operation.v1`

Required fields:
`schema`, `name`, `version`, `summary`, `inputSchemaRef`, `outputSchemaRef`,
`errorSchemaRef`, `mutationClass`, `idempotencyPolicy`, `authzPolicyRef`,
`requiredEvidenceKinds`, `supportedModes`, `supportedFaces`, `timeoutPolicy`,
`cancellationPolicy`.

Invariants:

- unique `(name, version)` identity and immutable per schema.
- all declared faces map to one canonical operation and one set of semantics.
- `supportedModes` is closed and explicit (`local` and `self_hosted` only in current scope).
- idempotency subject is deterministic for retry-safe operations and explicit for all writes.

### 7) `hasna.factory_api_envelope.v1`

Required fields:
`schema`, `requestId`, `traceId`, `operation`, `operationVersion`, `createdAt`.

Invariant shape:

Common fields are: `schema`, `requestId`, `traceId`, `operation`,
`operationVersion`, `createdAt`.

Result shape is supplied by the `ok`/`data`/`error`/`page`/`event` union:

- success: `{ ok: true, data, subjectDigest? }`
- failure: `{ ok: false, error: factory_error }`
- page: `{ ok: true, items, nextCursor?, itemCount, truncated: false }`
- stream: `{ ok: true, item: factory_event, sequence, resumeCursor }`

Invariants:

- payload is bounded and face-consistent.
- envelopes are canonical across faces.
- transport and status codes derive only from typed `factory_error` contracts.
- mode is not a common envelope field; transport and face context carries mode.

### 8) `hasna.factory_evidence_manifest.v1`

Required fields:
`schema`, `id`, `runRef`, `attemptRef`, `generation`, `repositoryRef`,
`baseSha`, `headSha`, `diffDigest`, `verificationPlanRef`, `requiredKinds`,
`evidenceRefs`, `completeness`, `createdAt`, `manifestDigest`.

Invariants:

- each evidence ref must be `hasna.evidence_ref.v1` and bound to same subject context.
- `completeness` can be `complete` only when all required kinds are present.
- `manifestDigest` must change when subject binding changes.
- manifest digest includes evidence ordering and immutable subject tuple.

### 9) `hasna.factory_attestation.v1`

Required fields:
`schema`, `id`, `kind`, `issuerRef`, `createdAt`, `expiresAt?`, `runRef?`,
`attemptRef?`, `generation?`, `authorityEpoch?`, `subject`, `policyDigest`,
`evidenceManifestRef`, `result`, `reason?`, `attestationDigest`.

Invariants:

- subject binding is mandatory and explicit for transition-bearing attestations.
- immutability after issuance; revocation/deprecation is represented by new superseding attestations only.
- no expiration extension is allowed after issuance.
- expiry or subject drift invalidates authority transition.
- any privilege transition requires matching exact subject and authority epoch.

## Implementation plan for future IAP9-00041

This document is implementation-shaped only; it does not execute code changes.

- add IDs, Zod schema definitions, types, and `ContractSchemaRegistry` entries in `src/schemas.ts`:
  - `hasna.factory_*` schema declarations
  - `SCHEMA_IDS` additions and type exports
  - schema registry wiring
- validate all entries through `src/validators.ts` and ensure lookup/build contracts remain total.
- expose root exports from `src/index.ts` for schema ids/types/validators used by external adapters.
- add minimal + complete valid examples and targeted invalid examples under `examples/`.
- add `tests/schemas.test.ts` coverage for:
  - required fields
  - strict unknown-key rejection
  - embedded-id mismatch
  - digest/hash mismatch
  - forbidden raw lease/credential/path/transcript payload
  - size bounds
  - enum and discriminator enforcement
  - terminal immutability
  - monotonic attempt/generation/event sequencing
  - stale fence behavior
  - evidence completeness checks
  - attestation subject drift rejection
  - closed-set enforcement for the `15` effects / `8` git publish stages
  - no merge mutation behavior
  - cross-face and local/self_hosted parity
- add fixture coverage in `tests/examples.test.ts` for the above contracts and examples.
- add focused property and cross-schema tests where invariants cross types (attempt-event linkage, attestation-subject linkage, and generation/fence monotonicity).
- add nine Factory-schema registry/embedded/strictness tests plus `task_to_pr_projection`
  interoperability assertions without duplicating runtime authority.
- generated `dist/` output remains build artifacts only; it is never hand-edited in source.
- release gates in this repo remain command-based and unchanged:
  - `bun install --frozen-lockfile`
  - `bun run todos:hygiene`
  - `bun run typecheck`
  - `bun test`
  - `bun run conformance`
  - `bun run build`
  - `bun run smoke:dist`
  - `bun run smoke:todos-pack`
  - `bun run pack:check`
  - `bun run verify:release` (aggregate gate; includes
    `bun run conformance`, `bun run build`, `bun run smoke:dist`,
    `bun run smoke:todos-pack`, `bun run pack:check`)
  - nonprinting staged/commit-range secrets scans
  - two independent exact-head adversarial reviews

## Validation evidence on the current base

Local aggregate gate results against base `6238e96476b26b950d0a20295f330bf6c0977e90`:

- `bun run verify:release` exited `0`.
- todos hygiene passed, typecheck passed, `bun test` = `401` passed / `7` skipped / `0` failed.
- example conformance passed, build passed, dist smoke passed, isolated Todos consumer passed, pack dry-run passed.

These local results are evidence-only and do not supersede the recorded hosted-verification `FAILURE` on merged PR #22.
Canonical/released Factory authority is not established because this task graph remains nonterminal and no exact released artifact/version/digest is pinned.

## PR/task boundaries

- `IAP9-00048` — completed predecessor architecture PR.
- `IAP9-00049` — current docs-only inventory pass.
- `IAP9-00041` — future Contracts schema implementation.
- `IAP9-00054` — planned Factory serializer/conformance adoption.
- `IAP9-00052` — adversarial review lane.
- `IAP9-00073` — landing task.

## Acceptance checklist for IAP9-00049

- [x] Current IAP9-00049 inventory, schema inventory, and implementation-shaped plan are fully present and internally consistent.
- [x] Confirms `15` effect kinds, `8` git.publish stages, and the corrected task graph/gate structure.
- [x] Confirms hosted facts and source references remain preserved, including current base `6238e...` unhealthy and PR #22 verification failure.
- [x] Verifies local aggregate gate on exact base via `bun run verify:release` with exact results:
  `401` passed, `7` skipped, `0` failed (`bun test`) and no failures from the aggregate gate.
- [x] Defers future schema/fixture/property implementation to IAP9-00041; none are claimed implemented in this docs-only PR.
- [x] Records exact-head adversarial/merge evidence and release posture as Todos/PR artifacts, not mutable document state.
