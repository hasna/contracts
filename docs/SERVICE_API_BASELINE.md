# Hasna Service/API Baseline

This standard defines the minimum service, API, schema, smoke, and evidence
surface for built `open-*` and `iapp-*` packages that expose a server, MCP
server, dashboard, worker, or externally documented API.

It is intentionally stricter than source presence. A package is not service
ready until the installed artifact passes the relevant checks below.

## Scope

Included packages:

- Built or partially built `open-*` and `iapp-*` apps.
- Server, MCP, CLI-token, SDK, dashboard, worker, and provider surfaces.

Excluded packages:

- `platform-*` apps.
- Empty, README-only, scaffold-only, stale clone-only, or license-only repos.
- CLI-only or library packages that explicitly declare unsupported service
  surfaces in `hasna.contract.json`.

Deployment mode vocabulary is `local`, `self-hosted`, and `cloud`.
`remote` is a location word, not a deployment mode.

## Contract Fields

Every onboarded repo must have `hasna.contract.json` validated by
`hasna.service_contract.v1`. The contract must identify:

- Package identity: package name, version source, repo path, and canonical app
  short name.
- Deployment mode support: `local`, `self-hosted`, `cloud`, or explicit
  unsupported reason per mode.
- Published bins: primary CLI, MCP, serve, worker, runner, daemon, migrate, and
  doctor bins when supported.
- Serve declaration: serve binary name, startup flags, lifecycle endpoints, and
  local bind policy.
- API policy: stable `/v1` namespace, legacy/internal route exceptions, error
  envelope, pagination, filtering, idempotency, request id, and deprecation
  headers.
- Schema exports: OpenAPI or equivalent machine schema path, SDK generation
  source, MCP tool schema source, and snapshot location.
- Surface matrix: CLI command, API route, MCP tool, SDK method, dashboard route,
  worker action, required auth mode, required scope, and support status for
  each golden-path operation.
- Storage mode: source of truth, migrations, readiness check, backup/restore
  evidence, and data lifecycle hooks.
- Auth modes: local operator, session token, API key, service token,
  machine/job token, and provider webhook.
- Worker/provider roles: queue names, leases, retries, dead letters, approval
  gates, sandbox/live readiness, and reconciliation status.
- Release smoke commands: pack/install smoke, lifecycle smoke, schema export,
  parity smoke, auth-negative smoke, no-secret output scan, and artifact scan.

## Serve Binary Baseline

Service packages must publish `<name>-serve` in `package.json`. CLI-only or
library packages must declare service support as unsupported with a reason.

Serve binaries must support:

- `--host`
- `--port`
- `--data-dir` or explicit storage URL/config reference
- `--json`
- `--version`

Startup must fail closed when required auth, storage, migrations, or secret
references are missing. Non-loopback binds require an explicit auth mode and
must not self-issue operator credentials.

## Lifecycle Endpoints

Every serve binary exposes:

- `GET /health`: process liveness only.
- `GET /ready`: readiness for the declared mode, including storage,
  migrations, queue leases, credential references, provider config, and worker
  dependencies when applicable.
- `GET /version`: package name, package version, git/build metadata when
  available, contract version, and surface versions.

Failures must be structured JSON and safe for logs. Responses must not include
credential values, raw provider tokens, private payloads, or full secret refs
when a redacted reference is enough.

## `/v1` API Policy

Stable product APIs live under `/v1`. Root-level lifecycle endpoints are the
only stable public routes outside `/v1`.

Existing `/api/*` routes must be one of:

- Bridged or redirected to `/v1`.
- Marked internal.
- Marked legacy with removal policy.

Common response rules:

- JSON error envelope with code, message, request id, and safe details.
- Pagination and filtering rules for list endpoints.
- `Idempotency-Key` for mutating routes where retries can duplicate effects.
- Request id propagation for API, CLI, MCP, SDK, and worker logs.
- Deprecation headers for legacy public routes.

Provider side-effect routes must split read-only, dry-run, approval-request,
execute, rollback/revoke, and reconciliation operations.

## Schema Export

Each service exposes machine-readable OpenAPI or an equivalent schema in both
source and package artifacts. The schema includes:

- Auth modes and scopes.
- Request and response bodies.
- Error envelope.
- Pagination and idempotency headers.
- Lifecycle endpoints.
- Version metadata.
- Unsupported or internal route markers.

SDKs and MCP tool schemas should be generated from, or checked against, the
same source schema. Drift must fail CI through deterministic schema snapshots.

## Surface Parity Matrix

Multi-surface packages must define golden-path operations and prove parity
across declared surfaces:

| Field | Meaning |
| --- | --- |
| `operation` | Stable operation name. |
| `cli` | CLI command and JSON mode. |
| `api` | `/v1` method and path. |
| `mcp` | MCP tool name. |
| `sdk` | SDK function or class method. |
| `dashboard` | Operator route or unsupported reason. |
| `worker` | Worker action or unsupported reason. |
| `auth` | Auth mode and required scope. |
| `idempotency` | Idempotency key or explicit not-applicable reason. |
| `status` | Supported, internal, legacy, unsupported, or planned. |

Unsupported surfaces must be tested as intentionally unavailable. Silent
absence is a failure.

## Package Smoke

Every publishable package must pass an installed-artifact smoke from an isolated
temp project:

1. Pack the package.
2. Install it without repo-relative imports.
3. Run every declared `--version` bin.
4. Import SDK exports.
5. Run CLI JSON help.
6. Start MCP when declared.
7. Start serve when declared and smoke lifecycle endpoints.
8. Verify schema artifacts exist.
9. Scan package artifacts for local state, benchmark data, screenshots,
   secrets, provider payloads, unrelated lockfiles, and generated scratch data.

Bun release-age quarantine stays enabled. Add exact Hasna package names to the
release-age exclusion registry only when a fresh internal package install
requires it.

Non-Bun packages must define native equivalents, for example Swift build/test,
Rust cargo build/test, Python build/pytest, or pnpm/Turbo pack/install smoke.

## Auth And Negative Tests

Every public route or surface declares auth mode and scope. Baseline negative
tests cover:

- Unauthenticated.
- Wrong token type.
- Missing scope.
- Wrong tenant, workspace, or entity.
- Revoked key.
- Expired token.
- Disabled token.
- Service token used on a human/session route.
- Unsafe non-loopback local bind.

Provider webhook tests cover valid signature, invalid signature, replay, stale
timestamp, oversized payload, wrong provider, and auditable failure.

Auth failures, diagnostics, CLI JSON output, MCP output, and API responses must
pass no-secret output scanning.

## Worker, Queue, And Provider Readiness

Worker/provider packages expose `/v1` status for:

- Queue depth.
- Active leases.
- Retries.
- Dead letters.
- Redelivery.
- Idempotency state.
- Approval requests.
- Rollback/revoke support.
- Reconciliation state.

Provider readiness states are:

- `disabled`
- `configured`
- `sandbox-ready`
- `live-read-ready`
- `live-side-effect-ready`

Side-effect execution cannot bypass approval in production/live modes. Read-only
live checks must prove they cannot mutate provider state.

## Readiness Evidence Bundle

Every readiness claim stores sanitized evidence with:

- Command.
- Timestamp.
- Package identity and version.
- Git head.
- Worktree path.
- Runtime mode.
- Data directory or redacted storage reference.
- Endpoint URL when applicable.
- Smoke output hash or artifact path.
- Verifier result.
- Staged secrets scan status before commit or publish.

Scorecards must distinguish static contract presence from live runtime proof.
Duplicate roots and package identity collisions are flagged, not counted twice.

## Adoption Checklist

- Add or update `hasna.contract.json`.
- Confirm package identity and canonical repo path.
- Declare supported deployment modes and unsupported reasons.
- Publish or explicitly reject `<name>-serve`.
- Implement `/health`, `/ready`, and `/version`.
- Place stable public APIs under `/v1`.
- Export OpenAPI or equivalent schema.
- Add schema snapshot drift test.
- Add parity matrix for golden-path operations.
- Add package pack/install smoke.
- Add auth-negative tests.
- Add provider webhook tests when applicable.
- Add worker/queue/provider readiness when applicable.
- Add no-secret output scans over CLI, MCP, API, SDK, and logs.
- Add readiness evidence bundle generation.

## First Adoption Candidates

| Wave | Repos | Focus |
| --- | --- | --- |
| Contract kit | `open-contracts`, `open-configs`, `open-deployment`, `open-releases`, `open-testers` | Schema, validators, smoke harnesses, scorecards. |
| Infra services | `open-backup`, `open-bridge`, `open-domains`, `open-gateway`, `open-hooks`, `open-machines`, `open-releases`, `open-secrets`, `open-servers`, `open-uptime`, `open-monitor`, `open-logs`, `open-repos`, `open-sandboxes`, `open-sessions`, `open-shield`, `open-security` | Serve bins, lifecycle, deployment contracts, auth-negative gates. |
| Finance/comms/customer | `open-accounting`, `open-banking`, `open-economy`, `open-conversations`, `open-mailery`, `open-telephony`, `open-tickets`, `open-feedback`, `open-contacts`, `open-calendar`, `open-shortlinks` | `/v1`, OpenAPI, webhooks, provider safety, queues, auth. |
| Data/AI/control | `open-attachments`, `open-files`, `open-knowledge`, `open-mementos`, `open-projects`, `open-search`, `open-todos`, `open-coders`, `open-codewith`, `open-connectors`, `open-dispatch`, `open-mcps`, `open-prompts`, `open-swarm`, `open-testers`, `open-browser`, `open-computer`, `open-terminal` | Parity, provenance, package smoke, operator status. |
| Internal iapps | `iapp-accounting`, `iapp-billing`, `iapp-payments`, `iapp-payroll`, `iapp-treasury`, `iapp-wallets`, `iapp-invoices`, `iapp-tax`, `iapp-access`, `iapp-controls`, `iapp-fleet`, `iapp-workforce`, `iapp-email`, `iapp-leads`, `iapp-ads`, `iapp-data`, `iapp-notes`, `iapp-signatures`, `iapp-sourcing`, `iapp-trademarks`, `iapp-transcriber`, `iapp-researcher` | Mode declarations, approvals, audit, reconciliation, provider and cost controls. |

## Reviewer Mapping

This document covers reviewer-09 `SVC-01` through `SVC-10`:

- `SVC-01`: contract fields and conformance source.
- `SVC-02`: serve binary naming and startup flags.
- `SVC-03`: health, readiness, and version endpoints.
- `SVC-04`: `/v1` API policy.
- `SVC-05`: OpenAPI/schema export.
- `SVC-06`: MCP/API/CLI/SDK/dashboard parity matrix.
- `SVC-07`: pack/install and artifact smoke.
- `SVC-08`: auth, scope, webhook, and negative tests.
- `SVC-09`: worker, queue, and provider readiness.
- `SVC-10`: readiness evidence bundle and scorecard.
