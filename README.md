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
const signingSecret = process.env.HASNA_TODOS_API_SIGNING_KEY!; // shared: HASNA_API_SIGNING_KEY
const { client } = createCloudPoolFromEnv(APP);                 // RDS pool (Amendment A1)
const keys = new ApiKeyStore(client);
await keys.ensureSchema();                                      // idempotent: api_keys table

app.use(
  expressApiKey({
    app: APP,
    signingSecret,
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

**Client env vars (self_hosted mode):** `<APP>_API_URL` + `<APP>_API_KEY` — never a DSN.

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

## SDK from OpenAPI (`@hasna/contracts/sdk`)

`generateSdkFromOpenApi(spec)` turns an `<app>-serve` OpenAPI 3 document into a
typed, dependency-free `fetch` client plus interfaces from `components.schemas`.
The generated client sends the API key as `x-api-key`, so a self_hosted consumer
only needs `<APP>_API_URL` + `<APP>_API_KEY`.

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
  without depending on shared `@hasna/cloud` or `open-cloud` runtimes.
- `hasna.no_cloud_evidence_pack.v1`: prepublish/CI evidence pack for package
  manifest, lockfile, source/runtime config, packed artifact, published
  metadata, and app-cloud-manifest scans.
- `hasna.service_contract.v1`: repo self-description (`hasna.contract.json`) for
  the Hasna Service Contract v1 — name, repo class, targeted contract version,
  tracked kit version, declared bins, and the `local | cloud` storage boundary.
  See `CONTRACT.md` for the normative spec and `contracts repo-conformance` /
  `runRepoConformance` for the self-check kit.

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

## Package Boundaries

`@hasna/contracts` owns schemas, types, validators, examples, and conformance
helpers. Owning packages still own storage and behavior.

- `open-todos` owns tasks, task plans, locks, comments, and task evidence.
- `open-loops` owns loop and workflow execution.
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
- `open-loops`: emit loop/workflow runs as `WorkRun`, audit traces as
  `AgentTrajectory`, logs/artifacts as `EvidenceRef`, and verifier output as
  `ProofBundle`. OpenLoops owns `WorkflowInvocation`, admission/work-item
  queues, leases, workflow runs, retries, cancellation, worktrees, and run
  artifacts.
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
  connector/action recipes. Any agentic task, PR, review, or evaluation flow
  must hand off to OpenLoops rather than creating a second workflow queue.
- `open-reports`: consume `ProofBundle`, `WorkRun`, `ContextPack`,
  `CostEstimate`, and `EvidenceRef` to render compact Markdown/JSON/HTML proof
  reports.
- Every package that implements app-owned cloud support should emit an
  `AppCloudManifest` and attach it to a `NoCloudEvidencePack` during release.
  The manifest names explicit app-owned resources and the evidence pack proves
  the package does not depend on `@hasna/cloud` or `open-cloud`.

## WorkflowInvocation And App Storage Boundary

The canonical agent-work root is a `WorkflowInvocation`, not a todo task.
Only actionable unfinished work needs a todo. OpenTodos remains the
human-visible intent ledger; OpenLoops owns the durable workflow root,
admission queue, execution lifecycle, and canonical run artifacts.

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

OpenLoops admission/work items are first-class records with route key,
idempotency key, source/subject refs, project key/group, priority, status,
attempts, next-attempt time, lease expiry, loop/workflow/run ids, and last
reason. Status values should be explicit: `queued`, `deferred`, `admitted`,
`running`, `succeeded`, `failed`, `dead_letter`, or `cancelled`.

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
packages need to validate the object directly at a shared boundary.

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

## Examples

The `examples/` directory contains one valid fixture for every known schema plus
targeted invalid fixtures for important invariants. Keep fixtures small and
portable. Prefer `artifact://`, `repo://`, `task://`, or package-owned ids over
machine-local paths.

The conformance command intentionally treats unknown schemas, malformed JSON,
and empty fixture sets as harness failures. Invalid fixtures must fail because
the schema rejected them, not because the fixture cannot be parsed.

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
