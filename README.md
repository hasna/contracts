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
- `hasna.context_pack.v1`: bounded context bundle with objective, resources,
  evidence, constraints, and token budget.
- `hasna.agent_trajectory.v1`: compact trace of agent steps, tool calls,
  decisions, blockers, and final outcome.
- `hasna.validation_plan.v1`: deterministic checks a package or agent should run.
- `hasna.proof_bundle.v1`: reviewable validation result that ties a subject to
  checks, evidence, verifier, and verdict.

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
| `open-sessions` | `session`, `run`, `machine`, `artifact` |
| `open-context` | `context_pack`, `file`, `url`, `knowledge` |
| `open-knowledge` / `open-mementos` | `knowledge`, `memento`, `context_pack` |
| `open-files` | `file`, `artifact`, `url` |
| `open-evals` | `eval`, `verification`, `report`, `proof_bundle` |
| `open-economy` | `cost`, `budget`; budget choices are emitted as `DecisionEnvelope` contracts, not resource kinds |
| `open-monitor` | `alert`, `incident`, `machine`, `report` |

## Package Boundaries

`@hasna/contracts` owns schemas, types, validators, examples, and conformance
helpers. Owning packages still own storage and behavior.

- `open-todos` owns tasks, task plans, locks, comments, and task evidence.
- `open-loops` owns loop and workflow execution.
- `open-actions` owns executable action manifests.
- `open-sessions` owns transcript and trajectory ingestion.
- `open-context` owns context-pack construction and retrieval.
- `open-knowledge` owns durable knowledge records and promotion workflows.
- `open-files` owns artifact storage, file indexing, and dereference logic.
- `open-mementos` owns memory lifecycle and recall.
- `open-reports` owns rendered reports and proof presentation.
- `open-evals` owns evaluation execution and scored validation results.
- `open-economy` owns budget, cost, and usage policy decisions.
- `open-monitor` owns fleet health classification and alerting.

## Downstream Integration Recipes

Adopt contracts as optional compact boundary output first. Prefer `--contract`
CLI flags, MCP response variants, or SDK adapter functions rather than replacing
native domain objects immediately.

- `open-files`: emit `ResourceRef`, `EvidenceRef`, and `ContextPack` for file
  records, versions, signed URLs, source manifests, and evidence assets.
- `open-todos`: expose task refs as `ResourceRef`; verification evidence as
  `ProofBundle`; task execution receipts as `WorkRun`; review gates as
  `ValidationPlan`.
- `open-loops`: emit loop/workflow runs as `WorkRun`, audit traces as
  `AgentTrajectory`, logs/artifacts as `EvidenceRef`, and verifier output as
  `ProofBundle`.
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
- `open-reports`: consume `ProofBundle`, `WorkRun`, `ContextPack`,
  `CostEstimate`, and `EvidenceRef` to render compact Markdown/JSON/HTML proof
  reports.

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

`verify:release` runs typecheck, tests, build, and a smoke test against the
packaged CLI entrypoint in `dist/cli/index.js`.
