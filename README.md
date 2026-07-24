# @hasna/contracts

Shared schemas, TypeScript types, validators, fixtures, and CLI checks for Hasna
open-source agent infrastructure.

`@hasna/contracts` is not a database, daemon, scheduler, or orchestrator. It is
the shared language used by the `open-*` packages when they exchange refs, runs,
decisions, costs, context packs, validation plans, trajectories, and proof
bundles.

## Purpose

Agents lose time and tokens when every package invents its own shape for
evidence, actors, runs, costs, decisions, and status. This package defines the
boring contracts those packages can validate at CLI, MCP, SDK, API, event, and
file boundaries.

The goal is to make integration work deterministic:

- Producers emit a small object with a known `schema` id.
- Consumers validate the object before spending model context on it.
- Failed validation returns concrete field errors instead of vague agent prose.
- Work products can link task ids, run ids, evidence ids, and proof ids without
  custom glue scripts.

## Install

```bash
bun add @hasna/contracts
```

## Todos contract

`@hasna/contracts/todos` is the pure customer contract for Todos. Import it
from the subpath; it is intentionally not exported from the package root.

```ts
import {
  TodosModeSchema,
  TodosTaskSchema,
  TODOS_OPERATION_MANIFEST,
} from "@hasna/contracts/todos";

const mode = TodosModeSchema.parse("local"); // "local" | "cloud"
```

Mode and authority selection are explicit data. The contract accepts exactly
`local` or `cloud`, binds one authority, and exposes the same shared customer
operation manifest across both modes. Local topology operations have no HTTP
mapping. Checked-in artifacts are available under
`@hasna/contracts/todos/artifacts/*`.

Authority discovery is fail-closed. Consumers must validate the authority
handshake with `TodosCanonicalAuthorityHandshakeSchema` or
`validateCanonicalTodosAuthorityHandshake`; a structurally valid handshake is
not canonical unless its contract digest, operation-manifest digest, and sorted
capability inventory exactly match this package.

The manifest is a required target contract, not an assertion about either
producer implementation. Every CLI, MCP, SDK, and shared HTTP mapping is marked
`required_target` with producer implementation status `not_attested`. The
manifest includes only customer and tenant-admin audiences. Shared HTTP
operations live under `/v1`; local topology operations intentionally have no
HTTP surface.

The v1 source boundary is frozen to:

- contracts base `0c8c5b4205ceaf16b1cee26c30199249055c934e`
- open Todos evidence `a18a8b797eb1b05e92964dbf8b036dde972c2314`
- platform Todos evidence `3d0bb21d586eed553e9010fc1187b19415958394`
- selective projection evidence `142e650c7f13d05ac145bd37e986e68909d571d2`

The operation manifest mechanically binds mutability, idempotency,
concurrency/precondition fields, task-transition targets, request schemas,
response schemas, and surface paths. The local `server.start` operation, for
example, requires the explicit `expectedState: "stopped"` precondition and
returns typed started-state data. Generated OpenAPI represents every GET
request field as an actual path or query parameter with schema-derived
requiredness; non-GET requests use typed JSON bodies.

Transfer bundles carry deterministic section counts and digests, a bundle
checksum, complete transitive foreign-key closure, dependency closure,
content-addressed attachments, reference-only identity inventories, and
fully-redacted deletion history. Every section, record, nested reference,
projection, closure entry, attachment, and inventory entry binds one source
authority. Portable command, evidence, run, and file records carry only
content-addressed or redacted metadata; raw command text, arguments, and
filesystem locations are rejected. Import plans, checkpoints, migration
receipts, and replay decisions bind the source and target authorities, current
contract and manifest digests, bundle id and digest, deterministic import-plan
id and content digest, and idempotency key. Within a receipt chain, one
idempotency key can commit exactly one canonical import tuple and terminal
result; an exact receipt replay is reported without appending another receipt,
while key reuse or a second commit is rejected. The package's public
checkpoint, transition, receipt, execution-context, and chain validators reject
otherwise well-formed historical digests; version-neutral structural schemas
remain internal to artifact generation. Use
`validateTodosTransferBundle`,
`validateTodosTransferCheckpointTransition`,
`validateTodosMigrationReceiptChain`, and `evaluateTodosImportExecution` at the
corresponding runtime boundaries.

Task-to-PR projections are append-only digest-linked records. A transferred
projection successor requires its exact predecessor record in the same
projection section, matched by owner, kind, projection id, immediately prior
version, and digest; missing-first, missing-middle, and substituted predecessor
histories are rejected. Validate both individual transitions and the complete
history:

```ts
import {
  validateTaskToPrProjectionHistory,
  validateTaskToPrProjectionTransition,
} from "@hasna/contracts/todos";
```

The generated JSON Schemas describe transport shape, but some canonical rules
cannot be expressed by JSON Schema alone. `invariant-registry.json`,
`schema-bundle.json`, and each affected schema's `x-hasna-invariants` extension
name the required runtime validator. Consumers must run those validators; they
must not treat JSON-Schema acceptance as proof of canonical authority,
invocation, transfer, replay, or projection-history integrity.

`contract.json` closes over the operation manifest, capability manifest, schema
bundle, invariant registry, source provenance, and generator identity digests.
`generator-provenance.json` records the exact frozen sources and semantic input
digests. `checksums.json` then closes over every generated file. This split
keeps schema hashing version-neutral and avoids a circular contract-digest
dependency while still making artifact tampering detectable.
The version-neutral schema foundation and runtime schema registry are internal
artifact-generation modules: `@hasna/contracts/todos` does not export their
registries, lookup or parser helpers, schema-bundle builder, or structural
digest constants, and no package subpath exposes those modules. Public
consumers can read generated JSON through
`@hasna/contracts/todos/artifacts/*`, but checkpoint and migration-receipt
runtime input must go through the canonical public schemas and helpers. The
public `TODOS_REQUEST_SCHEMAS` transfer-import execution entry and both
`TODOS_RESPONSE_SCHEMAS` migration-receipt entries apply those same current
contract and operation-manifest digest checks; the internal structural maps
remain available only to artifact generation and internal operation plumbing.

Regenerate and verify the deterministic artifacts with:

```bash
bun run todos:generate
bun run todos:check
bun run smoke:todos-pack
```

The packed-subpath smoke installs the produced `.tgz` into a separate consumer
with its own Zod dependency and imports
`@hasna/contracts/todos` plus JSON artifacts through package exports. It does
not reuse or symlink this repository's `node_modules`.

## CLI

The CLI is Bun-based. Use the package `bin` entries (`contracts` or
`contracts-cli`) from Bun/npm scripts; do not import `@hasna/contracts/cli` as a
Node library.

List known schema ids:

```bash
contracts schemas
contracts schemas --json
```

Validate a file using its embedded `schema` field:

```bash
contracts validate examples/evidence-ref.valid.json
```

Validate against an explicit schema id:

```bash
contracts validate --schema hasna.evidence_ref.v1 examples/evidence-ref.valid.json
```

Check package fixtures. Files ending in `.valid.json` must pass, and files
ending in `.invalid.json` must fail for schema reasons. Empty fixture sets,
unknown schemas, and malformed JSON are harness failures.

```bash
contracts conformance examples
contracts conformance --json examples
```

Scan a package source tree or packed `.tgz` before publishing. The scan focuses
on package manifests, lockfiles, source/runtime surfaces, config files, and
packed artifacts. It intentionally ignores docs/examples so packages can
document forbidden legacy edges without failing their own checks.

```bash
contracts no-cloud-scan .
contracts no-cloud-scan --json .
contracts no-cloud-scan --manifest app-cloud.manifest.json .
contracts no-cloud-scan --json hasna-todos-0.11.62.tgz
```

Print the shared secure local-store policy for `.hasna` and `.codewith`, or
produce a dry-run lifecycle plan for owner-only permissions and package-owned
retention adapters:

```bash
contracts secure-local-store --json
contracts secure-local-store --json --store todos
contracts secure-local-store "$HOME" --json --plan --store todos
contracts secure-local-store "$HOME" --json --apply --store todos
contracts secure-local-store "$HOME" --json --plan --retention --store todos --retention-proof todos-exports-backups
```

`secure-local-store` never reads file contents. The contract covers `0700`
directories, `0600` files, SQLite DB/WAL/SHM sidecars, backups, exports, active
record exclusions, artifact allowlists, and SQLite maintenance gates. Retention
and SQLite maintenance are dry-run by default and require explicit package
adapter proof before deletion or compaction.

## Storage Kit (vendored codegen)

`vendor-kit` stamps a canonical, self-contained Postgres storage kit into a
target repo at `src/generated/storage-kit/`. The kit is **vendored** (copied
source, zero runtime dependency on `@hasna/contracts`) and is **PURE REMOTE**
per Amendment A1: it contains no sync engine, no cache-as-mode, and no merge
logic. It ships:

| File            | Purpose                                                              |
| --------------- | ------------------------------------------------------------------- |
| `mode.ts`       | Storage-mode + env resolution (`local` \| `cloud`), per the contract |
| `tls.ts`        | The one correct TLS approach (libpq `sslmode` semantics + RDS CA)    |
| `pool.ts`       | `pg.Pool` factory (`createPgPool`, `createCloudPoolFromEnv`)         |
| `query.ts`      | Typed query wrapper: `query` / `many` / `get` / `one` / `execute`    |
| `migrations.ts` | `schema_migrations` ledger with sha256 checksums + drift guards      |
| `health.ts`     | `checkHealth` (SELECT 1) and `checkReady` (migrated?) probes         |

The host repo must provide `pg` (and `@types/pg`) as a dependency.

Stamp or refresh the kit (also writes `kitVersion` into `hasna.contract.json`):

```bash
bunx @hasna/contracts vendor-kit                 # into the current repo
bunx @hasna/contracts vendor-kit ./path/to/repo  # into another repo
bunx @hasna/contracts vendor-kit --no-contract .  # skip the manifest update
bunx @hasna/contracts vendor-kit --json .
```

Verify in CI — fails (exit 1) if the vendored kit is stale (an older
`@hasna/contracts` version) or hand-edited (content hash differs):

```bash
bunx @hasna/contracts vendor-kit --check .
bunx @hasna/contracts vendor-kit --check --json .
```

The generated files carry a `KIT_VERSION` header and are recorded in
`src/generated/storage-kit/.storage-kit-manifest.json`. Do not hand-edit them;
regenerate instead.

## Service/API Baseline

Built `open-*` and `iapp-*` packages that expose a server, MCP server,
dashboard, worker, or externally documented API follow the shared
[Service/API Baseline](docs/SERVICE_API_BASELINE.md). The baseline ties
`hasna.contract.json` to serve binaries, lifecycle endpoints, `/v1` policy,
OpenAPI/schema export, cross-surface parity, package smoke checks, auth-negative
tests, worker/provider readiness, and readiness evidence bundles.

## Durable Storage Readiness

Repos that claim shared, self-hosted, cloud, provider-live, finance, or
production readiness must also follow the
[Durable Storage Readiness Standard](docs/STORAGE_READINESS_STANDARD.md). The
standard covers source-of-truth declarations, Postgres migrations and drift
checks, RLS or equivalent boundary enforcement, backup/restore, retention,
delete/tombstones, conflict handling, TLS and credential posture, and readiness
evidence.

## API-Key Auth (`@hasna/contracts/auth`)

Stateless, verifiable API keys for the `<app>-serve` HTTP services. A key is an
HMAC-signed compact token with the human prefix `hasna_<app>_`; the signed claims
carry the app, scopes, and TTL, so verification needs **no** database round-trip.
Only the sha256 hash is stored at rest (the secret is shown once at issue time),
and revocation is layered on top via the key store.

**Exact import + usage every `<app>-serve` service calls** (Express shown; Hono
is identical via `honoApiKey`):

```ts
import { expressApiKey, ApiKeyStore } from "@hasna/contracts/auth";
import { createCloudPoolFromEnv } from "./generated/storage-kit"; // vendored kit

const APP = "todos";
const signingCredential = process.env.HASNA_TODOS_API_SIGNING_KEY!; // shared: HASNA_API_SIGNING_KEY
const { client } = createCloudPoolFromEnv(APP);                 // RDS pool (Amendment A1)
const keys = new ApiKeyStore(client);
await keys.ensureSchema();                                      // idempotent: api_keys table

app.use(
  expressApiKey({
    app: APP,
  signingSecret: signingCredential,
    isRevoked: keys.isRevoked,          // per-request revocation check against RDS
    requiredScopes: ["todos:read"],     // optional per-mount scope gate
    audit: (e) => log.info("api_auth", e), // per-request AUDIT hook (allow + deny)
  }),
);
// On success: req.apiKey = { kid, app, scopes, agent, claims }
```

Framework-agnostic core (for custom routers): `verifyApiKey({ app, signingSecret })`
returns `{ authenticate(headers, ctx) }`. Tokens are read from the `x-api-key`
header or `Authorization: Bearer <key>`.

**Serve env vars:**

| Env var                        | Purpose                                                    |
| ------------------------------ | ---------------------------------------------------------- |
| `HASNA_<APP>_API_SIGNING_KEY`  | HMAC signing secret (falls back to `HASNA_API_SIGNING_KEY`) |
| `HASNA_<APP>_DATABASE_URL`     | RDS URL for the `api_keys` store (revocation lookups)      |

**Client env vars (self_hosted mode):**

- `HASNA_<APP>_API_URL` + `HASNA_<APP>_API_KEY` — the explicit per-app URL
  always wins and is normalized to `/v1`. Explicit URLs require canonical ASCII
  authorities without credentials, controls, IDN/punycode, query strings, or
  fragments, parser-normalized host forms, or invalid DNS labels. HTTPS paths
  and ports are preserved; HTTP is accepted only for an exact loopback authority
  used by local development.
- If the per-app URL is blank or absent, a valid `HASNA_FLEET_API_DOMAIN`
  supplies the domain suffix for `https://<app>.<domain>/v1`.
- The composed `<app>.<domain>` host must remain within DNS label and total-name
  limits. If the fleet domain is missing, blank, malformed, or too long once the
  app prefix is added, resolution uses the app-specific neutral, non-resolving
  `https://<app>.your-deployment.example/v1` placeholder and marks the
  configuration `misconfigured`. The high-level client throws before
  constructing an authenticated transport, so an API key is never sent to the
  placeholder or to a parser-confused authority.
- Authenticated client requests never follow HTTP redirects. Every 3xx response,
  including a same-origin redirect, is returned as a fail-closed
  `HasnaHttpError`; API keys, bearer credentials, custom headers, and request
  bodies remain confined to the explicitly validated API origin.

The short aliases `<APP>_API_URL` and `<APP>_API_KEY` remain supported after the
canonical `HASNA_` names. Client configuration uses an HTTP API URL, never a
database DSN. When relying on the fleet-domain or neutral placeholder default, set
`HASNA_<APP>_STORAGE_MODE=cloud`; only an explicit URL + API-key pair infers
cloud mode when the mode variable is absent.

Scope grammar is `<app>:<action>` with wildcards (`*`, `<app>:*`, `*:<action>`).

### Issuing keys

```bash
# Mint a scoped key: stores the hashed record in RDS, prints the secret ONCE.
contracts issue-key --app todos --agent worker-1 --scopes 'todos:read,todos:write'

# Bootstrap admin key (scopes default to '<app>:*', agent 'bootstrap'):
contracts issue-key --app todos --bootstrap

# Print secret + hash without persisting (e.g. offline signing):
contracts issue-key --app todos --scopes 'todos:read' --no-store --json
```

Signing secret is read from `HASNA_<APP>_API_SIGNING_KEY` (then `HASNA_API_SIGNING_KEY`);
the record store uses `HASNA_<APP>_DATABASE_URL`. Generate a signing secret with
`openssl rand -hex 32`. Revoke with `store.revoke(kid)`.

Services that expose API, MCP, CLI-token, dashboard, worker, sync/export, or
provider webhook surfaces must also follow the shared
[Auth And RBAC Verifier Contract](docs/AUTH_RBAC_VERIFIER_CONTRACT.md). That
contract defines the common auth context, token types, scope and role matrix,
tenant/workspace/entity boundaries, provider webhook rules, audit events, and
negative-test matrix.

## SDK from OpenAPI (`@hasna/contracts/sdk`)

`generateSdkFromOpenApi(spec)` turns an `<app>-serve` OpenAPI 3 document into a
typed, dependency-free `fetch` client plus interfaces from `components.schemas`.
The generated client sends the API key as `x-api-key`, so a self_hosted consumer
only needs `HASNA_<APP>_API_URL` + `HASNA_<APP>_API_KEY`.

```ts
import { generateSdkFromOpenApi } from "@hasna/contracts/sdk";
const { code, operations, warnings } = generateSdkFromOpenApi(openapiDoc, { className: "TodosClient" });
// write `code` to the app SDK package's client.ts
```

## TypeScript

```ts
import {
  SCHEMA_IDS,
  parseEmbeddedContract,
  parseContract,
  validateEmbeddedContract,
  validateContract,
  type EvidenceRef,
  type EvidenceRefInput
} from "@hasna/contracts";

const draft: EvidenceRefInput = {
  schema: SCHEMA_IDS.evidenceRef,
  id: "ev_tests",
  createdAt: "2026-06-27T10:00:00.000Z",
  kind: "command_output",
  uri: "artifact://runs/run_123/tests.txt"
};

const result = validateContract(SCHEMA_IDS.evidenceRef, draft);
if (!result.success) {
  return { ok: false, issues: result.error.issues };
}

const evidence: EvidenceRef = parseContract(SCHEMA_IDS.evidenceRef, draft);
const embedded = validateEmbeddedContract(draft);
const parsedBySchemaField = parseEmbeddedContract(draft);
```

Use `validateContract` at boundaries when you want to return structured issues.
Use `parseContract` when invalid input should throw `ContractValidationError`.
Use `validateEmbeddedContract` or `parseEmbeddedContract` when the producer sends
a top-level object and the consumer should dispatch from its `schema` field.
Input aliases such as `EvidenceRefInput` describe producer payloads before Zod
defaults are applied; output aliases such as `EvidenceRef` describe parsed data.

## Contract Catalog

- `hasna.actor_ref.v1`: agent, human, service, model, workflow, or system actor.
- `hasna.resource_ref.v1`: portable reference to a task, repo, file, run,
  session, loop, knowledge item, report, proof bundle, or other shared resource.
- `hasna.evidence_ref.v1`: pointer to files, command output, screenshots, logs,
  diffs, reports, artifacts, URLs, videos, HAR captures, test results, metrics,
  traces, or other evidence.
- `hasna.work_run.v1`: normalized run receipt for agent, command, workflow, loop,
  eval, test, deploy, or review work.
- `hasna.task_to_pr_projection.v1`: immutable, provider-neutral identity
  projection for one task-to-PR attempt. It binds the Todos root/PR-group/leaf
  and replay cursor, the Codewith run/profile route, the Repos
  repo/worktree/branch/writer lease, exact-head review and merge-CAS refs,
  repair/recovery/cancellation preservation, cleanup, rollback, and optional
  OpenLoops invocation context without becoming a receipt, queue, store, or
  canonical history.
- `hasna.decision_envelope.v1`: decision record with selected/skipped
  resources, rationale, actor, costs, obligations, redactions, and evidence.
- `hasna.cost_estimate.v1`: money and token estimates with provider, model,
  account, basis, and resource references.
- `hasna.capability_card.v1`: machine-readable description of a package command,
  MCP tool, API operation, workflow, or agent skill.
- `hasna.provider_live_mode_standard.v1`: provider/live-mode standard with
  canonical modes, capability cards, fail-closed credentials, no-side-effect
  smokes, approval/idempotency/rollback/reconciliation gates, and first adopter
  targets.
- `hasna.context_pack.v1`: bounded context bundle with objective, resources,
  evidence, constraints, and token budget.
- `hasna.integration_ref.v1`: portable pointer to a project integration provider
  such as todos, files, mailery, conversations, knowledge, mementos, reports,
  actions, render, contracts, or a custom provider.
- `hasna.project_manifest.v1`: canonical agent-managed project manifest with
  slug, classification, `.hasna/project` layout, integrations, render manifests,
  resource refs, and evidence refs.
- `hasna.project_panel.v1`: compact provider output for a dashboard panel,
  including state, freshness, metrics, items, safe action refs, evidence, and an
  optional render fragment.
- `hasna.project_snapshot.v1`: bounded point-in-time project dashboard snapshot
  that groups panels, context packs, proof refs, resources, evidence, and
  freshness metadata for rendering.
- `hasna.render_manifest.v1`: project-local render manifest for JSON/render,
  React Flow/infinite canvas, report, document, or custom views with explicit
  import boundaries.
- `hasna.agent_trajectory.v1`: compact trace of agent steps, tool calls,
  decisions, blockers, and final outcome.
- `hasna.validation_plan.v1`: deterministic checks a package or agent should run.
- `hasna.proof_bundle.v1`: reviewable validation result that ties a subject to
  checks, evidence, verifier, and verdict.
- `hasna.scaffold_manifest.v1`: public, portable description of a scaffold's
  type, status, capabilities, output shape, env vars, scripts, and validation
  checks.
- `hasna.scaffold_install_record.v1`: portable receipt for a scaffold install
  against a target repo or project, including installer, status, generated
  resource refs, evidence, and proof refs.
- `hasna.app_cloud_manifest.v1`: app-owned cloud boundary declaration for a
  package that uses its own cloud resources, local cache, and conflict policy
  without depending on shared `@hasna/cloud` or `open-cloud` runtimes. This is
  NOT an identity schema: canonical app identity lives in `hasna.app.v1`, and
  this v1 manifest keeps `appId` as a non-empty reference string for
  compatibility; new manifests should use the stable `hasna.app.v1` slug.
- `hasna.secure_local_store_policy.v1`: shared `.hasna`/`.codewith` secure
  local-store lifecycle policy with owner-only modes, package inventory,
  retention adapters, active-record exclusions, artifact allowlists, and SQLite
  maintenance safety gates.
- `hasna.no_cloud_evidence_pack.v1`: prepublish/CI evidence pack for package
  manifest, lockfile, source/runtime config, packed artifact, published
  metadata, and app-cloud-manifest scans.
- `hasna.service_contract.v1`: repo self-description (`hasna.contract.json`) for
  the Hasna Service Contract v1 — name, repo class, targeted contract version,
  tracked kit version, declared bins, and the `local | cloud` storage boundary.
  See `CONTRACT.md` for the normative spec and `contracts repo-conformance` /
  `runRepoConformance` for the self-check kit.
- `hasna.comms_event_envelope.v1`: fleet comms event envelope carried in
  conversations message metadata — namespaced `<source>.<entity>.<action>` type,
  severity (`info | notice | breaking | critical`), scope
  (`fleet | package | machine`), `affected_packages`/`affected_machines`,
  `action_required`, `ack_by`, and a mandatory `dedupe_key`.
  `fleet.freeze`/`fleet.unfreeze` are pinned critical + fleet-scoped +
  action-required. The one severity mapping table ships as
  `COMMS_EVENT_TYPES`/`COMMS_SEVERITY_TAG_INFO`.
- `hasna.comms_channel_metadata.v1`: the object stored under a conversations
  channel's `metadata.channel_schema` key — channel `class`
  (`fleet | package | product | loop-lane | initiative | personal`), noise class
  (`quiet | work | firehose`), initiative `owner` + `until` horizon, and an
  optional archived-channel `successor` pointer.
- `hasna.comms_message_metadata.v1`: structured metadata for severity-tagged
  posts. The message text starts with `[FREEZE]`/`[UNFREEZE]`/`[BREAKING]`/
  `[CUTOVER]`/`[POLICY]`/`[RELEASE]` as its exact-case first token; the tag plus
  the full event envelope ride in `--metadata`, never parsed from text.
  Publishers, hooks, and loops validate with `validateCommsTaggedMessage`
  (or `extractCommsSeverityTag` + `validateContract`) before emit/post. The
  human-facing rules live in knowledge items `hasna-agent-comms-protocol` /
  `hasna-agent-comms-envelope`; these schemas are the machine-validatable
  source of truth.
- `hasna.app.v1`: canonical app identity for the distribution apps plan —
  stable `appId` slug, `npmName`, `repoFolder`, `githubUrl`, `projectSlug`,
  surfaces (`bins`, optional `mcp`/`http`), lifecycle
  (`active|stub|deprecated|archived`), and release channel. All other
  distribution documents reference apps by `appId` only.
- `hasna.release.v1`: publish receipt for one app package version — `appId`,
  `package`, semver `version`, `gitSha`, `publishedAt`, publish path
  (`skill|ci|backfilled`), optional deferred `changelogRef`, and publish
  evidence (required unless backfilled).
- `hasna.rollout_record.v1`: per-machine rollout receipt — `appId`, `package`,
  `version`, `machine`, action (`install|update|rollback|freeze-blocked`),
  contract-status `result`, `verifiedBy` with at least one verifier field for
  successful install/update records (`cliVersion` or checked `mcpHealth`), and
  `at`.
- `hasna.announcement.v1`: release/campaign announcement receipt — `campaignId`,
  optional `appId` and `releaseRef`, per-channel delivery statuses, an
  `audienceRef` (resource kind `audience`), and `sentAt`.
- `hasna.audience.v1`: named audience definition — `audienceId`, tag/attribute/
  group predicates with `all|any` matching, consent policy
  (`opt_in|opt_out|transactional|none`), and `suppressionSyncedAt`.

Every top-level contract includes a literal `schema` field. Consumers should
reject objects whose embedded schema does not match the validator being used.
Top-level `EvidenceRef` documents are dereferenceable and require a URI; nested
evidence pointers may be compact `{ id }` links when the enclosing bundle or
store can resolve them.

Capability cards use compact kinds: package commands, MCP tools, and API
operations map to `tool`; workflow runners map to `service` or `lane`; agent
skills map to `agent`; model routes map to `model`; connectors map to
`connector`.

Common resource-kind mappings:

| Repo domain | Preferred resource kinds |
| --- | --- |
| `open-todos` | `task`, `project`, `verification`, `proof_bundle` |
| `open-loops` | `loop`, `workflow`, `run`, `artifact` |
| `open-actions` | `action`, `tool`, `event`; decisions are emitted as `DecisionEnvelope` contracts, not resource kinds |
| `open-automations` | `action`, `tool`, `event`; deterministic recipe decisions are emitted as `DecisionEnvelope` contracts |
| `open-sessions` | `session`, `run`, `machine`, `artifact` |
| `open-context` | `context_pack`, `file`, `url`, `knowledge` |
| `open-knowledge` / `open-mementos` | `knowledge`, `memento`, `context_pack` |
| `open-files` | `file`, `document`, `artifact`, `url` |
| `open-mailery` | `email`, `document`, `artifact` |
| `open-conversations` | `conversation`, `comment`, `event` |
| `open-projects` | `project`, `dashboard`, `render`, `panel`, `integration` |
| `open-evals` | `eval`, `verification`, `report`, `proof_bundle` |
| `open-economy` | `cost`, `budget`; budget choices are emitted as `DecisionEnvelope` contracts, not resource kinds |
| `open-monitor` | `alert`, `incident`, `machine`, `report` |

## Task-to-PR projection

`TaskToPrProjection` is a strict reference projection, not a `WorkReceipt`,
`PRReceipt`, queue, database, event store, or replacement for any owning
package. `WorkRun` remains the execution receipt. `EvidenceRef` and
`ProofBundle` remain evidence and verification records; `DecisionEnvelope`
remains a decision record; `CapabilityCard` remains an admission snapshot;
`ResourcePointer` remains a generic resource link; and `AgentTrajectory`
remains a bounded trace. The projection only binds their owner-resolved refs.

Authority is fixed:

- Todos owns the canonical root request, PR group, leaf task, attempt,
  writer generation, terminal disposition, repair state, and append-only
  lifecycle history.
- Codewith owns durable run admission, worker actor and assignment, opaque
  profile/route selection, and runtime state.
- Repos owns repository, worktree, branch, writer lease/fence refs, and cleanup.
- Infinity may execute an admitted attempt but is only an adapter; it does not
  become an authority or history store.
- TAI may render the projection read-only; it does not write lifecycle state.
- OpenLoops may contribute one optional invocation ref as orchestration
  context. It owns no Codewith goal, Todos task or history, Repos lease,
  review, merge guard, or merge outcome.

Every `TaskToPrRef` has one role, one allowed authority, one lowercase SHA-256
owner-record digest, one explicit redaction state, and one structural
nonsemantic id:
`role:authority:opaque-<first-32-hex-characters-of-digest>`. This makes owner
resolution schema-driven rather than dependent on a semantic-keyword blacklist.
Canonical objects are dereferenced from their owning packages instead of
embedded as mutable payloads. The projection id
(`task_to_pr_projection:opaque-*`) and attempt nonce
(`attempt_nonce:opaque-*`) each require an independent 128-bit lowercase
hexadecimal surrogate.
`TaskToPrEvidenceRef` is deliberately smaller than `EvidencePointer`: it only
allows `evidence:opaque-<first-32-hex-characters-of-digest>`, the immutable
digest, and `partial`/`full` redaction, so a
projection cannot inline a URI, summary, command output, or secret-adjacent
payload.

| Projection field | Cardinality | Authority and invariant |
| --- | --- | --- |
| `workRunRef` | exactly 1 | Codewith; points to the existing `WorkRun` receipt |
| `rootRequestRef` / `prGroupRef` / `leafTaskRef` | exactly 1 each | Todos; immutable canonical identities |
| `attempt.ref` / `attempt.nonce` | exactly 1 each | Todos attempt identity; every retry uses a fresh nonce |
| admission / worker actor / worker assignment / runtime refs | exactly 1 each | distinct redacted Codewith owner records; admission carries an exact writer-generation binding, and every successor attempt rotates admission and assignment in addition to the attempt-scoped runtime identity |
| writer generation / lease / fence refs | exactly 1 each | generation is Todos-bound; lease/fence are redacted Repos refs, never a fence value |
| provider profile / route refs | exactly 1 each | redacted opaque Codewith refs; never provider account or credential data |
| repo / worktree / branch plus base and branch heads | exactly 1 binding | canonical Repos refs with exact Git object ids |
| event stream / replay cursor / sequence / prefix digest | exactly 1 cursor | Todos append-only history is referenced, never copied; sequences are nonnegative safe integers |
| `handoff` | 0 or 1 current transition | Todos ref binding prior/next attempts, prior/next generations, and the prior WorkRun plus distinct stop and revocation evidence identities/digests; the full record is immutable under one canonical ref, while a later handoff requires both a fresh canonical role/authority/id and a fresh digest; mutually exclusive with recovery |
| `pullRequestRef` | 0 or 1 | Todos PR-group identity; required by review or merge state |
| exact-head proof | required before review/merge | exact expected base = provider PR base and local head = remote head = provider PR head, with equality and CI proof refs; same-base/head facts are immutable and every base/head change requires fresh proof identities and digests |
| `reviews` | 0 or more unique exact-base/exact-head reviews | review ref, reviewer/run, proof bundle, PR, immutable base, and immutable head; same-base/head history preserves the prior array as an exact immutable prefix and can only append, while a changed base or head requires fresh review, review-run, and proof-bundle identities and digests |
| `repair` | exactly 1 state | cumulative Todos cycle `0..2`; never decrements or resets; entering `repairing` consumes exactly one new cycle, exhausted work cannot re-enter repair, and repair state freezes after terminal disposition |
| merge guard / outcome | 0 or 1 each | guard binds reviewed base/head and proof; only `merge_ready` may carry `eligible`, terminal outcomes require a `consumed` guard, and failed/blocked/cancelled history may only retain a revoked guard; outcome classifies base drift independently from head drift and binds the exact immutable guard |
| recovery / cancellation | recovery is mutually exclusive with handoff and cancellation; 0 or 1 each | preservation refs are an exact one-per-role set for root/group/leaf/repo/worktree/branch/event and present PR; recovery binds canonically distinct prior attempt/generation/WorkRun refs, distinct stop/revocation evidence, and a fresh successor nonce/generation |
| `terminalDispositionRef` | exactly 1 in terminal states; absent otherwise | durable Todos owner fact for the terminal disposition; immutable after establishment |
| cleanup eligibility / outcome | 0 or 1 each | Repos-owned; eligibility binds the terminal disposition, current replay cursor, exact writer lease, canonical worktree, distinct lease-revocation and consumed-event evidence, and must be `eligible` before deletion; outcome binds the exact eligibility decision |
| rollback plan / outcome | 0 or 1 each | plan targets a commit or branch, remains immutable under one canonical ref, and uses a fresh canonical id and digest when the plan or target changes; immutable outcome binds the exact plan and target |
| `provenanceLedger` | exactly 1 append-only identity ledger | immutable exact-prefix tombstones for the stable projection id, WorkRun, attempt, admission, worker actor/assignment, nonce, runtime, writer generation/lease/fence, provider profile/route, replay cursor/prefix, repair state/latest repair, handoff, recovery, merge guard, cleanup eligibility, rollback plan, terminal disposition, and base/head-bound equality/CI/review/provider-receipt identities; active identities must be represented exactly and all ref ids/digests share one global uniqueness domain |
| OpenLoops invocation | 0 or 1 | optional redacted context only |
| adapter extensions | 0 or more unique mode/schema pairs | `local` or `cloud` ref plus digest only; every extension schema must use the permanently reserved `hasna.task_to_pr_adapter_extension.*` namespace |

The top-level document deliberately has `createdAt` but no `updatedAt`.
Producers emit immutable snapshots under one stable top-level projection id;
the Todos stream/cursor remains the only canonical lifecycle history. Any
semantic change requires replay-sequence advancement with a fresh cursor and
prefix digest. `provenanceLedger` is not another event store: it is an
identity-only exact-prefix index over that history. Head-bound entries carry
both base and head, while admission, worker assignment, terminal disposition,
attempt nonce, and replay-prefix facts remain independently replay-safe. Ref
equality is exact across role, authority, id, digest, and redaction.

`validateTaskToPrProjectionTransition` parses both snapshots before comparing
them. It rejects top-level id changes, identity-scope mutation, replay
regression, sequence advances without a fresh cursor/prefix, semantic drift
without an event advance, provenance truncation/reordering/mutation, inactive
identity reactivation, illegal lifecycle edges, partial attempt lineage
rotation, and successor attempts that reuse admission, worker assignment,
runtime, lease, fence, profile, or route identities. Handoff/recovery must bind
the immediately prior attempt, generation, and WorkRun; recovery and
cancellation preservation lists must contain exactly the required roles with
no duplicates or extras. Repair entry advances exactly one cycle, cannot occur
after exhaustion, and repair is immutable after terminal disposition.
Same-base/head exact-head and review facts remain immutable prefixes; a base or
head change rotates equality, CI, review, review-run, review-proof, and provider
receipt identities. Terminal disposition plus complete merge, cancellation,
cleanup, and rollback owner facts are immutable once present.
`admitted`, `running`, and `handed_off` snapshots cannot carry direct review
bindings or hidden merge-guard review refs, including on a denied guard. A
`reviewing` to `recovering` transition may retain the exact same-head
`exactHead` and review prefix, but recovery cannot invent them from a pre-review
snapshot or carry merge-guard review refs. Same-head reviews can only be appended after the exact prior array
prefix; reordering or prepending invalidates the transition. This schema has no review
supersession field, so producers must advance the reviewed head before emitting
a replacement review set. `merge_ready` is the only state that can carry an
`eligible` guard. Eligible and consumed guards require
`attempt.admissionWriterGenerationRef` to exactly equal the current
`attempt.writerGenerationRef`, so a stale admission cannot survive writer
generation rollover into merge readiness or a terminal merge outcome. A
terminal merge outcome requires the same guard authority
facts in `consumed` state; because guard owner records are immutable, consumption or
revocation uses a fresh guard ref/digest while preserving the eligible guard's
exact PR, base/head, review/proof, operator, provider-receipt, and mechanism
facts. Failed, blocked, and cancelled projections cannot retain eligibility.
Failed and blocked are durable terminal dispositions and do not advertise a
transition back to `recovering`; `merge_ready` must revoke into a supported
non-recovery state before any later recovery attempt. Direct
nonterminal-to-`cleanup_complete` edges are illegal, and a
destructive cleanup decision must prove terminal disposition, writer-lease
revocation, and consumption of the terminal event.
Consumers must reject unknown fields rather than retain unvalidated embedded
payloads.

The exhaustive merge-authority matrix is:

| Projection state | Allowed merge authority |
| --- | --- |
| admitted, running, handed_off, reviewing, repairing, recovering | absent, denied-without-outcome, or revoked-without-outcome |
| merge_ready | eligible without outcome |
| merged | consumed with `merged` outcome |
| closed_unmerged | consumed with `closed_unmerged`, `refused`, `head_drift`, or `base_drift` outcome |
| failed, blocked, cancelled | absent or revoked-without-outcome |
| cleanup_complete | absent, revoked-without-outcome, or a previously consumed terminal outcome |
| rolled_back | consumed with `merged` outcome |

`canonicalizationVersion: 2` derives `identityDigest` from the ordered,
domain-separated tuple of role, authority, id, and digest for root request, PR
group, leaf task, repository, worktree, and branch, followed by the exact base
Git object id and frozen-scope digest. `canonicalizationVersion: 1` remains an
explicit legacy compatibility path using the prior root/group/leaf/repository
id/digest tuple and never silently upgrades to v2. The PR-group owner digest is
an input, never the derived output, so the binding has no circular dependency.
Digests on refs mean
the SHA-256 of the owning package's canonical, redacted record identity bytes;
they must never hash a credential, raw fence value, mutable payload, or
provider account record.

Exact base/head binding is transitive: `remoteBranchRef` equals the canonical
repository branch ref; `expectedBase`, provider pull-request base, repository
base, every review base, guard base, outcome expected base, and all
base/head-bound provenance entries agree. The local, remote, and provider
pull-request heads are equal and backed by equality plus CI proof refs.
Equality, every CI proof, and every review proof obligation are globally unique
by canonical ref id and digest, so one proof cannot discharge two obligations.
An eligible merge guard references the exact canonical set of approved review
refs with no extras or omissions, every review proof, every CI proof, the
equality proof, an opaque provider receipt, and its CAS/expected-head mechanism.
A merged outcome observes the same base and head. Only `head_drift` may carry a
mismatched observed head and only `base_drift` may carry a mismatched observed
base; each drift outcome keeps the other dimension equal. Exact-head
verification, reviews, guard evaluation, and merge outcome are chronologically
ordered.

Sensitive refs (`writer_lease`, `writer_fence`, `provider_profile`,
`provider_route`, `admission`, worker/runtime refs, `worktree`,
merge-provider refs, and adapter extensions)
require `partial` or `full` redaction. Strict objects reject fields such as
provider account ids, credentials, raw fence tokens, or embedded adapter
payloads. Local and cloud adapters serialize the same shared projection and
place provider-specific detail behind separately validated, redacted extension
refs. Extension schemas use the permanently reserved
`hasna.task_to_pr_adapter_extension.*` namespace, so adding unrelated canonical
schemas to `SCHEMA_IDS` cannot make previously accepted adapter data ambiguous.
`validateTaskToPrAdapterCoreEquivalence` parses both documents, requires
one or more local-only extensions in its first argument and one or more
cloud-only extensions in its second, removes only those validated
`adapterExtensions`, and requires byte-equivalent local and cloud core
projection data, including the complete cumulative provenance ledger.

## Package Boundaries

`@hasna/contracts` owns schemas, types, validators, examples, and conformance
helpers. Owning packages still own storage and behavior.

- `open-todos` owns tasks, task plans, locks, comments, and task evidence.
- `open-loops` owns its own loop and workflow execution. In task-to-PR flows,
  its invocation is optional reference-only orchestration context and confers
  no authority over Codewith, Todos, Repos, review, or merge state.
- `open-events` owns event envelopes, channels, delivery, replay, and
  notification semantics.
- `open-actions` owns executable action manifests.
- `open-automations` owns deterministic product/app automations and
  connector/action recipes. It does not own agent workflow invocation,
  admission queues, task/PR/review worker routing, or canonical workflow run
  artifacts.
- `open-sessions` owns transcript and trajectory ingestion.
- `open-context` owns context-pack construction and retrieval.
- `open-knowledge` owns durable knowledge records and promotion workflows under
  `.hasna/knowledge`.
- `open-files` owns artifact storage, file indexing, and dereference logic.
- `open-projects` owns project folder discovery, `.hasna/project` conventions,
  dashboard snapshot assembly, render manifest loading, and the local dashboard
  viewer. It validates project manifests, panels, snapshots, and render
  manifests with `@hasna/contracts`.
- `open-mementos` owns memory lifecycle and recall.
- `open-reports` owns rendered reports and proof presentation.
- `open-evals` owns evaluation execution and scored validation results.
- `open-economy` owns budget, cost, and usage policy decisions.
- `open-monitor` owns fleet health classification and alerting.
- `iapp-scaffolds` owns scaffold templates, registry behavior, install/setup
  behavior, MCP tools, CLI UX, and private/internal scaffold metadata. It should
  validate public scaffold manifests and install records with
  `@hasna/contracts`, but `@hasna/contracts` must not import or execute
  `iapp-scaffolds`.
- Each open-source app that needs cloud support owns that cloud integration in
  its own package and can publish an `AppCloudManifest`. `@hasna/contracts`
  validates the boundary, but it must not become a shared cloud runtime.
- `@hasna/cloud` and `open-cloud` are forbidden shared runtime dependencies for
  new app-owned cloud support. Use `NoCloudEvidencePack` and
  `contracts no-cloud-scan` in prepublish/CI checks to prove package manifests,
  locks, source/runtime config, and packed artifacts do not reintroduce them.

## Downstream Integration Recipes

Adopt contracts as optional compact boundary output first. Prefer `--contract`
CLI flags, MCP response variants, or SDK adapter functions rather than replacing
native domain objects immediately.

- `open-files`: emit `ResourceRef`, `EvidenceRef`, and `ContextPack` for file
  records, versions, signed URLs, source manifests, and evidence assets.
- `open-todos`: expose task refs as `ResourceRef`; verification evidence as
  `ProofBundle`; task execution receipts as `WorkRun`; review gates as
  `ValidationPlan`; and workflow/run manifest pointers as compact task fields,
  not embedded handoff artifacts.
- `open-loops`: emit its own loop/workflow runs as `WorkRun`, audit traces as
  `AgentTrajectory`, logs/artifacts as `EvidenceRef`, and verifier output as
  `ProofBundle`. A task-to-PR adapter may add one redacted
  `openLoopsInvocationRef`, but must not own or mirror the task-to-PR queue,
  Todos history, Codewith admission/runtime state, Repos leases/worktrees,
  review, or merge state.
- `open-events`: emit and replay validated event envelopes to channels.
  OpenEvents delivers notifications only; it does not create workflow
  invocations, own queue state, or retry agent work.
- `open-sessions`: convert messages/tool calls to `AgentTrajectory`, token
  usage to `CostEstimate`, and transcript paths to `EvidenceRef`.
- `open-context`: serialize built context as `ContextPack` with citations as
  `EvidenceRef` and source chunks as `ResourceRef`.
- `open-knowledge`: return retrieval results as `ContextPack`; write policy and
  promotion decisions as `DecisionEnvelope`.
- `open-mementos`: expose memories as `ResourceRef` kind `memento` or
  `knowledge`; reflection runs as `WorkRun`.
- `open-evals`: map cases/assertions to `ValidationPlan`, runs/results to
  `ProofBundle`, reports to `EvidenceRef`, and judge/baseline choices to
  `DecisionEnvelope`.
- `open-economy`: own `CostEstimate` production and emit budget decisions as
  `DecisionEnvelope`.
- `open-monitor`: output doctor checks, fleet triage, and alerts as
  `ValidationPlan`, `ProofBundle`, `EvidenceRef`, `alert`, and `incident`
  resources.
- `open-actions`: keep domain action manifests, but expose shared `ActorRef`,
  `EvidenceRef`, `CapabilityCard`, `DecisionEnvelope`, and `WorkRun` adapter
  views.
- `iapp-scaffolds`: emit `ScaffoldManifest` documents for bundled templates,
  write schema-tagged `ScaffoldInstallRecord` receipts for installs, and keep
  template copying, setup wizards, source paths, and private metadata inside the
  scaffold package.
- `open-automations`: keep deterministic app/product automation recipes and
  connector/action recipes. Agentic task, PR, and review flows hand off to the
  canonical Todos/Codewith/Repos owners rather than creating a second queue.
- `open-reports`: consume `ProofBundle`, `WorkRun`, `ContextPack`,
  `CostEstimate`, and `EvidenceRef` to render compact Markdown/JSON/HTML proof
  reports.
- Every package that implements app-owned cloud support should emit an
  `AppCloudManifest` and attach it to a `NoCloudEvidencePack` during release.
  The manifest names explicit app-owned resources and the evidence pack proves
  the package does not depend on `@hasna/cloud` or `open-cloud`.

## WorkflowInvocation And App Storage Boundary

For task-to-PR work, the canonical root is the Todos root request and PR-group
history referenced by `TaskToPrProjection`; it is not a `WorkflowInvocation`.
Codewith owns durable admission/profile/runtime state and Repos owns
repo/worktree/writer-lease/cleanup state. A `WorkflowInvocation` can still be
useful inside OpenLoops' own workflow domain, but a task-to-PR projection may
only carry it as optional orchestration context.

A workflow invocation should carry these fields at the boundary:

- `id`
- `templateId` or `workflowId`
- `sourceRef`: a WorkflowInvocation-local source kind such as `task`, `event`,
  `schedule`, `manual`, `pull_request`, `review`, or `knowledge`, plus an id
  and dedupe key
- `subjectRef`: a WorkflowInvocation-local subject kind such as `repo`,
  `pull_request`, `task`, `document`, `run`, or `metric`, plus a path, URL, or
  id
- `intent`: `route`, `mutate`, `review`, `evaluate`, or `report`
- `scope`: project path, worktree policy, permissions, account policy, and
  concurrency group
- `outputPolicy`: when to write reports and when to create a follow-up task

OpenLoops admission/work items remain first-class records only for OpenLoops'
own workflow execution. They must not be interpreted as task-to-PR attempts,
writer leases, repair counters, review records, merge guards, or canonical
lifecycle history.

Run artifacts live under:

```text
.hasna/loops/runs/<project-slug>/<subject-key>/<run-id>/manifest.json
.hasna/loops/runs/<project-slug>/<subject-key>/<run-id>/triage.md
.hasna/loops/runs/<project-slug>/<subject-key>/<run-id>/plan.md
.hasna/loops/runs/<project-slug>/<subject-key>/<run-id>/worker-report.md
.hasna/loops/runs/<project-slug>/<subject-key>/<run-id>/evaluation.md
.hasna/loops/runs/<project-slug>/<subject-key>/<run-id>/evidence/
```

The `<subject-key>` is never the raw subject reference. It must be a safe path
segment derived as `kind-safeSlug-shortHash`. Recommended normalization:
lowercase ASCII, replace non-alphanumeric runs with `-`, trim separators, cap
the slug portion at 72 characters, and append at least 12 hex characters from a
SHA-256 hash of the canonical raw `subjectRef`. Reject `.`/`..`, reserved device
names, path separators, empty keys, and path traversal. Store the raw
`subjectRef` only inside `manifest.json`.

OpenEvents webhooks/channels are notifications. A `task.created` notification
can be delivered through OpenEvents, but OpenLoops consumes the envelope and
upserts/admits work items. OpenEvents must not import OpenLoops or own
admission, retries, leases, verifier execution, or workflow run artifacts.

Every Hasna app stores local state under `.hasna/<app>/...`. The obsolete
`.hasna/apps/<app>` layout is not an operational read path. OpenKnowledge's
canonical storage is `.hasna/knowledge`, not `.hasna/apps/knowledge`.

No-backcompat migrations must preserve data without keeping legacy shims:

1. Create a read-only backup or export before moving data.
2. Atomically copy or rename into the canonical `.hasna/<app>` path.
3. Verify JSON item counts, SQLite integrity and table counts, artifact counts,
   hashes, and any storage-object or sync-snapshot evidence.
4. Leave only a diagnostic tombstone at the old path.
5. Treat mismatched counts, hash failures, or SQLite integrity failures as
   blockers.

Unattended automatic routes must fail closed when the configured sandbox cannot
be proven. Acceptable sandbox evidence includes a successful preflight receipt
that names the isolation provider, filesystem/network policy, writable roots,
tool allowlist, environment redaction result, and timestamp for the exact route
or run. `danger-full-access` plus a worktree is a manual break-glass mode, not a
safe auto-route default.

`WorkflowInvocation` is documented here as the architecture boundary used by
OpenLoops and neighboring packages. It is not yet a wire schema in the current
catalog; add a `hasna.workflow_invocation.v1` schema only when at least two
packages need to validate the object directly at a shared boundary. That
future schema would remain separate from `hasna.task_to_pr_projection.v1`.

## Enforcement Model

Validate at every boundary where another package, agent, process, or machine can
consume the object:

- CLI: fail with non-zero exit and structured JSON when `--json` is requested.
- SDK/API: reject invalid input before writing to storage or launching work.
- MCP/tool responses: validate outbound payloads before returning to the model.
- Events/webhooks: validate before publish and before handler execution.
- Files/artifacts: validate before using persisted JSON as evidence.
- CI/release: run `bun run verify:release` before publishing.

Invalid contracts should fail early at the boundary, not after another agent has
spent context trying to repair ambiguous data.

## Versioning

Schema ids are immutable, and current wire schemas are strict about unknown
fields. Breaking changes create a new id, such as `hasna.proof_bundle.v2`.
Additive fields may extend the current version only after a coordinated
validator rollout reaches consumers that will receive those fields. If older
validators can still consume the object, keep emitting only the old field set.
If producers need to emit the new field before that rollout is complete, create
a new schema id instead.

Recommended rollout for a new major schema:

1. Add the new schema and examples in this package.
2. Keep the old schema exported while consumers migrate.
3. Teach producers to emit the new schema behind a feature flag or option.
4. Teach consumers to accept both versions when practical.
5. Remove old-version production only after downstream repos have release notes
   and migration tasks.

During dual-version windows, consumers should inspect the embedded `schema` via
`validateEmbeddedContract`, route accepted ids to version-specific adapters, and
reject unknown schema ids before writing data or launching work.

`hasna.task_to_pr_projection.v1` is a new strict schema id; it does not widen
`hasna.work_run.v1` or any other existing v1 validator. The package source line
advances to `0.6.0` because registry/consumer evidence already showed `0.5.2`
while the repository still reported `0.5.1`. No package publish is performed
by this source change. Existing v1 inputs continue to parse unchanged, and
producers opt into the new projection explicitly by its embedded schema id.

## Examples

The `examples/` directory contains one valid fixture for every known schema plus
targeted invalid fixtures for important invariants. Keep fixtures small and
portable. Prefer `artifact://`, `repo://`, `task://`, or package-owned ids over
machine-local paths.

The conformance command intentionally treats unknown schemas, malformed JSON,
and empty fixture sets as harness failures. Invalid fixtures must fail because
the schema rejected them, not because the fixture cannot be parsed.

## Infra Service Entrypoints

Service-capable infra repos should declare supported, deferred, or unsupported
HTTP/MCP service surfaces in `hasna.contract.json` instead of adding `*-serve`
bins mechanically. The current Worker 2 baseline matrix is in
[`docs/infra-service-entrypoint-matrix.md`](docs/infra-service-entrypoint-matrix.md).

## Verification

```bash
bun run typecheck
bun test
bun run build
bun run smoke:dist
bun run verify:release
```

`verify:release` runs typecheck, tests, example conformance, build, a smoke test
against the packaged CLI entrypoint in `dist/cli/index.js`, and a pack dry-run.
