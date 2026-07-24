# Deployment Control Plane Contract

<!-- markdownlint-disable MD013 -->

Status: proposed, execution-free design contract

Date: 2026-07-24

Owning package: `@hasna/contracts`

Implementation task: `bdf41dd2-18be-4a54-97fd-cdfdfacfc869`

This document defines the versioned ownership, record, operation, concurrency,
evidence, and adoption contract for a private deployment control plane. It is a
design contract only. This documentation change does **not** add a schema,
validator, export, fixture, migration, provider adapter, worker, API route, or
deployment implementation.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used as
described by RFC 2119.

## 1. Status and implementation boundary

The target contract set is planned. A future implementation change must add and
test the machine-readable schemas before any producer may claim conformance.

| Contract surface | Status at this document's base | Rule for this document |
| --- | --- | --- |
| `ActorRef` / `hasna.actor_ref.v1` | Implemented | Reuse for canonical actors; use the existing pointer form only where a nested pointer is appropriate. |
| `EvidenceRef` / `hasna.evidence_ref.v1` | Implemented | Reuse for dereferenceable evidence; deployment profiles may make its optional digest mandatory. |
| `ResourceRef` / `hasna.resource_ref.v1` | Implemented | Reuse for portable resource links where a domain-specific immutable ref is not required. |
| `DecisionEnvelope` / `hasna.decision_envelope.v1` | Implemented and strict | Compose into deployment approvals; do not alter its v1 semantics. |
| `ValidationPlan`, `WorkRun`, and `CostEstimate` | Implemented | Reuse only where their current semantics fit. |
| `ProviderCapabilityCard` | Implemented as a reusable provider shape | Reuse or reference an immutable snapshot; do not invent a top-level schema claim in this docs change. |
| Deployment records in section 4 | Planned | No machine-readable implementation is claimed by this document. |
| `hasna.service_contract.v2` | Planned | Must coexist with v1 and ship through a separate implementation change. |
| Deployment operation registry contract | Planned | The registry design is normative; no registry code is added here. |
| Deployment event envelope | Planned | Domain semantics are defined here; durable delivery remains an OpenEvents responsibility. |

`@hasna/contracts` is a schema, type, validator, fixture, and conformance
package. It is not a deployment database, workflow engine, provider adapter,
credential broker, Terraform runner, or AWS writer.

## 2. Control-plane ownership

The deployment lifecycle is a chain of independently owned, immutable inputs.
No downstream system may silently take ownership of an upstream fact.

```text
Projects ───────────────> ProductProjection
App repository ─────────> IntentSnapshot
Factory ────────────────> VerifiedSourceCandidate
Build authority ────────> BuildArtifact + ArtifactAttestation
                                      │
EnvironmentBinding + ProviderCapabilityCard + observed state
                                      │
                                      ▼
DeploymentRequest → DeploymentPlan → bounded approval-decision set
                                      │
                                      ▼
                              DeploymentAttempt
                                      │
                                      ▼
                    ProviderReceipt → DeploymentReceipt
                                      │
                                      ▼
                               LaunchEvidence
```

### 2.1 Authoritative writers

| Record or state | Authoritative writer | Deployment's role | Explicit non-owners |
| --- | --- | --- | --- |
| Product and project identity | Projects | Consume a versioned `ProductProjection`. | Deployment, Factory, build pipelines, Terraform, and providers MUST NOT rewrite project identity. |
| Application deployment intent | The application repository at an immutable commit and tree | Validate and consume an `IntentSnapshot`. | Projects, Deployment, Factory, and Terraform MUST NOT synthesize intent that the repository did not declare. |
| Source verification candidate | Factory or the approved source-verification workflow | Consume `VerifiedSourceCandidate` as evidence that a source revision passed stated checks. | Factory is not the artifact builder and MUST NOT call a branch, commit, or pull request a deployable artifact. |
| OCI artifact and build provenance | The reusable build authority in `hasna-xyz-infra` or its successor | Require exact digests and attestations. | Deployment, Factory, and Terraform MUST NOT rebuild or retag source into an authoritative artifact. |
| Provider capability description | The package that owns the provider adapter | Select only operations allowed by a pinned `ProviderCapabilityCard` snapshot. | UI, CLI, MCP, plan compilers, and workers MUST NOT invent provider capabilities. |
| Environment binding | Deployment | Create and update a versioned binding through authorized, concurrency-checked operations. | Projects, app repositories, providers, and Terraform MUST NOT rewrite Deployment's binding record. |
| Commercial relationship | Billing or Economy | Store only a versioned opaque `CommercialBindingRef`, when applicable. | Deployment MUST NOT become pricing, billing, settlement, or entitlement authority. |
| Plans, approvals, attempts, and deployment receipts | Deployment | Authoritative writer. | Surfaces and providers MUST NOT create alternate deployment ledgers. |
| Provider-side operation result | The provider adapter from the provider response and later observation | Normalize to `ProviderReceipt` without replacing raw provider identity with local identity. | UI and clients MUST NOT fabricate provider success. |
| Production cloud resources | Terraform through the reviewed infrastructure pipeline | Submit a digest-bound request and observe results. | Application workflows, Deployment workers, CLIs, MCP tools, and dashboards MUST NOT make parallel production resource writes. |
| Observed provider state | The provider, read through an authorized adapter | Record a time-bounded observation and reconcile it with desired state. | Terraform state and Deployment records MUST NOT be described as live provider truth. |
| Schemas and validators | `@hasna/contracts` | Publish versioned contract implementations and conformance checks. | Domain producers MUST NOT publish incompatible private copies under the same schema identifier. |

Terraform is the only production infrastructure writer. Terraform state is
reconciliation metadata, not provider truth. Promotion and rollback are new
plans; they are not direct mutation shortcuts around this ownership model.

### 2.2 Separation of duties

Production policy MUST be able to distinguish requester, planner, approver,
executor, auditor, and administrator actors. A deployment profile MAY allow one
actor to hold multiple roles in local development, but it MUST NOT erase the
roles from the records.

Each approval decision authorizes one bounded subject: either the immutable
parent plan or one explicit action or phase plus its exact runtime
execution-material digest, target environment, and attempt scope. A gated
attempt MAY require an ordered set of decisions. An unchanged retry covered by
the applicable decision MUST NOT create a duplicate approval prompt in CLI,
MCP, API, GitHub, or Terraform, but any changed bound input requires a new
decision.

## 3. Common contract rules

Every planned top-level deployment record follows these rules.

### 3.1 Envelope and identity

A top-level record MUST contain:

- a globally unique, stable `id`;
- an exact versioned `schema` identifier;
- `createdAt` and, when mutable, `updatedAt`;
- an owning aggregate or subject reference;
- the actor responsible for the write, represented by `ActorRef` or a valid
  nested actor pointer;
- immutable source references or source digests;
- evidence references where the record asserts verification or observation;
- a monotonically increasing `revision` when the record is mutable;
- a canonical-content digest when another decision binds to the record.

IDs MUST NOT encode mutable display names, provider secrets, credentials, or
environment-specific authorization. A local UUID MUST NOT be sent to a provider
in place of the provider's own project, operation, deployment, resource, or
event identifier.

### 3.2 Immutability profiles

The following are immutable snapshots once accepted:

- `ProductProjection`;
- `IntentSnapshot`;
- `VerifiedSourceCandidate`;
- `BuildArtifact`;
- `ArtifactAttestation`;
- `DeploymentRequest`;
- an issued `DeploymentPlan`;
- an issued `DeploymentApprovalDecision`;
- `ProviderReceipt`;
- `DeploymentReceipt`;
- `LaunchEvidence`.

A correction creates a new record that links to the superseded record. It does
not overwrite evidence that was used by an earlier plan.

`EnvironmentBinding`, provider connections, a
`DeploymentPlanLifecycleProjection`, and a current attempt header may advance
by compare-and-swap. Their immutable history and step ledgers remain
append-only. The lifecycle projection is a rebuildable read model, not part of
the immutable plan or its canonical digest.

### 3.3 Canonical serialization and digests

Any digest-bound record MUST define deterministic canonical JSON serialization.
The canonical form MUST:

- sort object keys deterministically;
- preserve array order only where order is semantically meaningful;
- reject duplicate semantic identifiers;
- exclude transport-only fields such as request IDs;
- include the exact schema identifier and schema major;
- include referenced record IDs, revisions, and immutable digests;
- reject non-finite numbers and ambiguous timestamps.

Plan and approval digests MUST be SHA-256 over the canonical bytes. A consumer
MUST NOT approve or execute a plan it cannot canonicalize with the same
contract-kit version.

### 3.4 Secret and executable-content prohibition

No deployment contract may contain:

- a raw secret, token, password, private key, credential, database URL, or
  unredacted secret reference payload;
- a shell command, script, command-line fragment, interpreter directive, or
  templated command;
- an arbitrary environment-variable map;
- an arbitrary provider request body or raw provider state dump;
- a callback body that has not been reduced to a typed, redacted event;
- serialized Terraform state;
- executable hooks or user-provided code.

Secret and credential references MAY appear only as typed, opaque references
whose values are resolved transiently inside the authorized worker or provider
injection channel. Resolved values MUST NOT be persisted, serialized, logged,
audited, returned, or written to Terraform state.

## 4. Planned record catalog

The schema identifiers in this section are the proposed stable identifiers for
the first machine-readable implementation. They remain planned until added to
the package's schema registry, exports, JSON Schemas, fixtures, and tests.

| Type | Proposed schema identifier | Writer |
| --- | --- | --- |
| `ProductProjection` | `hasna.product_projection.v1` | Projects projection publisher |
| `IntentSnapshot` | `hasna.intent_snapshot.v1` | App-intent snapshot publisher |
| `VerifiedSourceCandidate` | `hasna.verified_source_candidate.v1` | Factory or source-verification workflow |
| `BuildArtifact` | `hasna.build_artifact.v1` | Build authority |
| `ArtifactAttestation` | `hasna.artifact_attestation.v1` | Build, signing, scanning, or policy authority |
| `EnvironmentBinding` | `hasna.environment_binding.v1` | Deployment |
| `CommercialBindingRef` | `hasna.commercial_binding_ref.v1` | Billing or Economy projection publisher |
| `DeploymentRequest` | `hasna.deployment_request.v1` | Deployment request boundary |
| `DeploymentPlan` | `hasna.deployment_plan.v1` | Deployment plan compiler |
| `DeploymentPlanLifecycleProjection` | `hasna.deployment_plan_lifecycle_projection.v1` | Deployment event projector |
| `DeploymentApprovalDecision` | `hasna.deployment_approval_decision.v1` | Deployment authorization boundary |
| `DeploymentAttempt` | `hasna.deployment_attempt.v1` | Deployment worker and reconciler |
| `ProviderReceipt` | `hasna.provider_receipt.v1` | Provider adapter |
| `DeploymentReceipt` | `hasna.deployment_receipt.v1` | Deployment verifier |
| `LaunchEvidence` | `hasna.launch_evidence.v1` | Deployment launch-evidence compiler |
| `DeploymentEventEnvelope` | `hasna.deployment_event_envelope.v1` | Deployment transactional outbox |

### 4.1 `ProductProjection`

`ProductProjection` is Deployment's immutable view of Projects-owned identity.
It MUST include:

- the Projects product or project ID;
- the source record version or revision;
- canonical slug and display identity;
- repository and workspace references;
- lifecycle classification and ownership references;
- the projection timestamp and producer actor;
- a source digest or source evidence reference.

The projection MUST NOT contain Deployment-owned environment bindings, provider
connections, plans, or attempts. When Projects changes, Deployment consumes a
new projection; it does not mutate the old one.

### 4.2 `IntentSnapshot`

`IntentSnapshot` is an immutable, commit-bound description of what an
application requires. It MUST bind:

- product projection ID and revision;
- repository, commit, and tree identity;
- intent-document path and digest;
- runtime processes and their typed roles;
- ports, liveness, readiness, and version endpoints;
- CPU, memory, scaling, and availability requirements;
- database, object storage, queue, worker, and cron requirements;
- migration compatibility and ordering;
- access, network, backup, restore, alarm, and rollback classes;
- typed configuration and secret-reference requirements, never values;
- validation evidence and producer actor.

Intent is declarative. It MUST NOT contain provider API requests, Terraform
expressions, shell commands, deployment action nodes, or environment-variable
maps.

### 4.3 `VerifiedSourceCandidate`

`VerifiedSourceCandidate` states exactly which source revision passed which
source checks. It MUST include:

- repository, commit, and tree identity;
- related branch or pull-request references when applicable;
- the `IntentSnapshot` ID and digest evaluated;
- review, test, policy, and source-integrity results;
- the validation plan or evidence references;
- verifier actors and timestamps;
- a status that distinguishes candidate, verified, rejected, and superseded.

This record is not a build artifact and MUST NOT imply that an image exists,
that a tag is immutable, or that the source is deployed.

### 4.4 `BuildArtifact`

`BuildArtifact` identifies immutable output from the build authority. It MUST
include:

- artifact kind and media type;
- an immutable registry or artifact URI;
- the authoritative content digest;
- the source candidate ID, repository commit, and tree digest;
- build workflow identity and build run reference;
- builder actor;
- created timestamp;
- related SBOM, provenance, scan, and signature evidence references;
- an optional supersession or revocation status.

A mutable tag MAY be descriptive metadata, but it MUST NOT be the identity used
by a plan. Deployment plans bind the immutable digest.

### 4.5 `ArtifactAttestation`

`ArtifactAttestation` binds one or more verifiable claims to the exact
`BuildArtifact` digest. It MUST include:

- the subject artifact ID and digest;
- predicate kind and predicate schema version;
- issuer or signer actor and key reference, never key material;
- signature or verification reference;
- policy result and policy revision;
- creation and optional expiry timestamps;
- evidence references for provenance, SBOM, scans, and verification.

An attestation MUST fail validation when its subject digest does not match the
artifact. A plan compiler MUST NOT silently transfer an attestation from one
digest to another.

### 4.6 `EnvironmentBinding`

`EnvironmentBinding` maps a product and immutable intent profile to one target
environment. It MUST include:

- product projection ID and revision;
- environment identity and classification;
- deployment mode (`local`, `self-hosted`, or `cloud`);
- provider connection reference and provider capability snapshot digest;
- typed account, region, cluster, network, storage, and routing locators;
- policy, authorization, data-classification, backup, and rollback profiles;
- optional `CommercialBindingRef`;
- current revision and ETag;
- writer actor and change evidence.

The binding MUST contain opaque provider and secret references, not credential
values. Updates require `If-Match` and an allowed compare-and-swap transition.

### 4.7 `CommercialBindingRef`

`CommercialBindingRef` is an optional, opaque projection of commercial
authority. It MUST include:

- the external commercial record ID;
- owner package or service;
- version or revision;
- applicability and status;
- an optional entitlement or policy digest;
- evidence that the reference was resolved.

It MUST NOT duplicate pricing, settlement, margins, payment credentials, or
customer-visible execution pricing inside Deployment. Non-commercial internal
applications may omit it.

### 4.8 `DeploymentRequest`

`DeploymentRequest` is the normalized client intent presented to the plan
compiler. It MUST include:

- request kind: `deployment`, `promotion`, `rollback`, or `reconciliation`;
- requester `ActorRef`;
- product projection and target `EnvironmentBinding` revisions;
- requested `IntentSnapshot`;
- immutable artifact and required attestation references, or a prior receipt
  for promotion or rollback;
- requested policy profile;
- client idempotency key fingerprint reference;
- request timestamp and optional expiry;
- source request and audit correlation IDs.

A request is not executable. It MUST NOT include provider calls, action code,
secret values, or an approval result.

### 4.9 `DeploymentPlan`

`DeploymentPlan` is an immutable, closed, typed action DAG compiled from a
validated request and pinned inputs. It MUST include:

- plan kind and request ID;
- plan compiler and contract-kit versions;
- all input IDs, revisions, and digests;
- provider capability snapshot digests;
- a complete action DAG as defined in section 6;
- authorization, policy, risk, and evidence requirements;
- expected state and verification criteria;
- rollback target and rollback-plan inputs;
- plan digest;
- issuance timestamp and optional expiry.

Changing any input, action, dependency, policy, artifact, binding revision, or
verification criterion creates a new plan and digest.

Compiler workflow states such as `draft`, `checked`, and `approval_required`
MUST NOT be serialized into an issued plan. An issued plan MAY define an
ordered `generate execution material → decide phase → apply exact material`
action sequence. Runtime material that does not exist at issuance, such as a
saved Terraform plan, is not and cannot be pre-digested by the parent plan.
Instead, the parent plan binds the generation inputs and requires a later
phase-scoped decision over the generated material before its apply action.

#### 4.9.1 `DeploymentPlanLifecycleProjection`

`DeploymentPlanLifecycleProjection` is a derived, rebuildable read model keyed
by the immutable plan ID and digest. It exposes lifecycle state as `issued`,
`approved`, `rejected`, `expired`, or `superseded`, together with the effective
decision references, latest attempt references and states, projection revision,
and observation timestamp.

The projection MUST be driven by the immutable plan and append-only approval,
attempt, expiry, and supersession events. It MUST NOT be embedded in the
`DeploymentPlan`, included in canonical plan serialization, or used as the
authorization artifact for execution. Rebuilding or advancing the projection
does not change the plan digest.

### 4.10 `DeploymentApprovalDecision`

`DeploymentApprovalDecision` composes the existing strict
`DecisionEnvelope.v1`; it does not modify that contract. It MUST additionally
bind:

- the exact plan ID and digest;
- decision scope: the parent plan or one explicit action or phase;
- the action and phase identifiers when phase-scoped;
- the exact runtime execution-material kind and digest when the action consumes
  material generated after plan issuance;
- the current backend, workspace, state lineage, and pre-action state serial
  when infrastructure state is in scope;
- the exact artifact, variable-set, provider-lock, policy, and other input
  digests required by the scoped action;
- target environment ID and revision;
- decision actor and actor role;
- decision status;
- approved attempt scope and unchanged-retry policy;
- issued and expiry timestamps;
- separation-of-duties evaluation;
- authorization-policy revision;
- obligations and evidence references.

The decision is an immutable authorization record independent of the immutable
plan. A parent-plan decision does not pre-authorize an unknown future runtime
execution-material digest and does not replace a required phase-scoped
decision. A phase-scoped decision MUST be issued only after its runtime
material exists. An approval for one digest, state lineage or serial, artifact,
or input set MUST NOT authorize another; any changed bound input requires a new
decision. Expired, revoked, superseded, or rejected decisions fail closed.

### 4.11 `DeploymentAttempt`

`DeploymentAttempt` is the durable execution aggregate for one immutable parent
plan and its required decision set. It MUST include:

- the parent plan ID and digest;
- the ordered set of required approval-decision IDs and digests, including
  their bound action or phase and runtime execution-material digests;
- requester, decision actors, and executor actors;
- environment lock ID and monotonic fencing token;
- attempt number and unchanged-retry lineage;
- state and revision;
- immutable action-step ledger;
- exact provider correlation IDs;
- outbox and inbox correlation references;
- cancellation, failure, unknown-outcome, and reconciliation state;
- evidence and provider receipt references;
- final deployment receipt reference when successful.

Recommended states are `queued`, `running`, `reconciling`,
`unknown_outcome`, `succeeded`, `failed`, and `cancelled`. The implementation
MAY add states in a compatible schema revision, but it MUST define allowed
transitions and compare-and-swap guards.

### 4.12 `ProviderReceipt`

`ProviderReceipt` is a redacted normalization of one provider operation. It
MUST include:

- provider, adapter, connection, and capability snapshot identifiers;
- operation registry ID and version;
- provider project, operation, deployment, resource, and event IDs when
  returned;
- request fingerprint, never a secret-bearing request body;
- provider status and normalized result;
- observed provider revision or timestamp;
- retry, reconciliation, and unknown-outcome classification;
- redaction state;
- response and observation evidence references.

A provider acknowledgement is not sufficient evidence of successful
deployment. Later observation and verification remain distinct.

### 4.13 `DeploymentReceipt`

`DeploymentReceipt` is the immutable control-plane result for a completed or
terminal attempt. It MUST include:

- request, parent-plan, ordered decision-set, and attempt references;
- product, intent, artifact, attestation, and environment revisions;
- provider receipt references;
- final desired and observed state digests;
- health, readiness, version, migration, alarm, and access verification;
- infrastructure plan and state-lineage references when applicable;
- rollback target;
- verifier actors and evidence;
- outcome: `succeeded`, `failed`, `cancelled`, or `unknown_outcome`.

Only a receipt with a successful outcome and passing required verification may
be used as the source of a promotion plan.

### 4.14 `LaunchEvidence`

`LaunchEvidence` is a bounded proof bundle for a release or rollout claim. It
MUST include:

- the product and target environment;
- current deployment receipt;
- required contract, security, migration, restore, rollback, alarm, and
  operational checks;
- evidence and proof-bundle references;
- unresolved findings grouped by severity;
- verifier actors and review independence;
- status: `candidate`, `blocked`, `ready`, `launched`, or `rolled_back`;
- compilation timestamp and an expiry or freshness policy.

The absence of evidence is not passing evidence. A `launched` status MUST NOT be
emitted while a required check is missing, expired, failed, or blocked.

## 5. One operation registry for every surface

There MUST be one machine-readable operation registry for the deployment
service. It is the source for OpenAPI, SDK, CLI, MCP, UI actions, worker
dispatch, authorization checks, and parity tests.

`@hasna/contracts` owns the registry schema. Deployment owns the concrete
registry entries. Generated surfaces are consumers and MUST NOT maintain
independent security or mutation definitions.

Each operation entry MUST declare:

| Field | Requirement |
| --- | --- |
| `operationId` and version | Stable, namespaced identity referenced by plan actions and receipts. |
| Input and output schemas | Exact `@hasna/contracts` identifiers. |
| Operation class | Read, plan, decide, execute, cancel, reconcile, verify, or administer. |
| Resource boundary | Product, environment, plan, attempt, provider connection, or evidence scope. |
| Permission and actor constraints | Required Access permission, allowed actor kinds, and separation-of-duties rules. |
| Risk and side-effect class | Must align with the provider operation card where a provider is used. |
| Approval rule | Whether approval is required and which parent plan, action or phase, runtime execution-material digest, state input, or revision it binds. |
| Idempotency policy | Required, optional, or not applicable; fingerprint and replay behavior. |
| Concurrency policy | ETag, compare-and-swap, lock, or immutable. |
| Execution mode | Synchronous read, asynchronous command, or transactional enqueue. |
| Audit and redaction profile | Required audit event, safe fields, prohibited fields, and retention class. |
| Evidence requirements | Evidence required before, during, and after execution. |
| Provider capability requirement | Provider operation and allowed modes, if applicable. |
| Surface support | API, SDK, CLI, MCP, UI, and worker support or an explicit unsupported reason. |

The generated operation names and surface adapters may differ syntactically,
but they MUST resolve to the same registry entry. An operation unavailable on a
surface is explicitly `unsupported`, `internal`, `legacy`, or `planned`; silent
absence fails parity validation.

MCP defaults to viewer and planner operations. Raw secrets, arbitrary callbacks,
arbitrary hooks, direct resource destruction, break-glass operations, and
unbounded provider mutation MUST NOT be exposed through MCP.

## 6. Typed action DAG

A `DeploymentPlan` contains a closed directed acyclic graph of typed actions.
The DAG describes authorized intent; it contains no executable code.

### 6.1 Action node

Every node MUST contain:

- a unique action ID within the plan;
- a versioned operation registry ID;
- dependency action IDs;
- typed input references and their expected revisions or digests;
- the output schema identifier;
- precondition and postcondition identifiers;
- resource-lock and fencing requirements;
- side-effect and risk classes;
- decision scope and runtime execution-material binding requirements when an
  action consumes material generated after plan issuance;
- provider capability operation and snapshot digest when applicable;
- retry class and bounded retry policy;
- timeout class, not an arbitrary command timeout script;
- compensation or rollback operation ID when required;
- audit, redaction, and evidence requirements.

Input values are contract data or immutable references. The worker resolves the
operation ID to reviewed implementation code; the plan never supplies code to
the worker.

### 6.2 Graph invariants

The complete contract-set validator MUST reject a plan unless:

- action IDs are unique;
- every dependency resolves inside the same plan;
- the graph is acyclic and has deterministic ordering;
- all input records exist and match the pinned schema, revision, and digest;
- every operation exists at the pinned registry version;
- provider actions are allowed by the pinned capability card and mode;
- every side effect is covered by policy and the applicable ordered approval
  decisions;
- runtime execution material generated after plan issuance is bound by a fresh
  scoped decision before any consuming side effect;
- every live mutation has idempotency, rollback or revocation, and
  reconciliation behavior;
- every required output is consumed or declared terminal;
- every terminal path produces failure or success evidence;
- rollback and promotion inputs resolve to immutable prior receipts;
- the canonical plan digest matches the serialized graph.

The validator MUST reject fields or aliases that introduce shell, script,
environment-map, raw state, raw provider body, or secret-bearing escape
hatches. A generic metadata object MUST NOT be interpreted as executable input.

Initial operation namespaces may include source verification, artifact
verification, environment locking, provider planning, migration staging,
migration execution, workload update, observation, reconciliation, health
verification, receipt issuance, and evidence compilation. The operation
registry, not this prose list, is authoritative.

## 7. Idempotency, concurrency, and worker correctness

### 7.1 Boundary idempotency

Every mutation that can duplicate work MUST require an `Idempotency-Key` across
API, SDK, CLI, MCP, and UI-generated requests.

The server derives a fingerprint from:

- actor and authorization boundary;
- operation registry ID and version;
- target resource;
- input schema;
- canonical input digest.

Reusing a key with the same fingerprint replays the original result or returns
the original asynchronous resource. Reusing it with a different fingerprint
returns a typed conflict and performs no work.

Idempotency records MUST be scoped, durable, expiry-aware, and safe for audit.
Raw secrets and full authorization tokens MUST NOT be part of a stored
fingerprint.

### 7.2 ETag and `If-Match`

Mutable public resources, including environment bindings and provider
connections, MUST return an ETag derived from the resource ID and revision.
Mutation requires `If-Match`.

- Missing `If-Match` fails with a typed precondition-required result.
- A stale ETag fails with a typed precondition-failed result.
- The server MUST NOT merge conflicting writes silently.
- A successful update increments the revision and emits a new ETag.

Immutable records use their digest and do not accept update operations.

### 7.3 Compare-and-swap and fencing

Internal state transitions MUST compare:

- expected aggregate revision;
- allowed previous state;
- environment lock identity;
- current monotonic fencing token.

A worker holding a stale fencing token MUST be unable to write attempt state,
provider receipts, or completion evidence. Takeover creates a higher token and
is recorded in audit.

The worker model is at-least-once delivery with idempotent effects, not a claim
of magical exactly-once execution. It MUST use:

- an immutable action-step ledger;
- transactional outbox;
- deduplicating inbox;
- bounded retry and dead-letter handling;
- exact provider correlation IDs;
- reconciliation before retrying an unknown-outcome create;
- append-only, redacted audit.

## 8. `hasna.service_contract.v2`

The existing `hasna.service_contract.v1` remains readable. Its additive
capability fields may evolve compatibly under the rules in Section 10.1; the
four-surface, hosting, storage-engine, and canonical `self_hosted` declarations
land in v1 because old readers can ignore them safely. The only intentional v1
validation tightening is that an explicitly declared SQLite path must end in
`.db`.

Deployment's accepted same-origin API path is `/api/v1`; v1 currently models a
root `/vN` base path. Supporting `/api/vN` therefore requires a deliberate v2,
not a silent relaxation of the v1 schema.

The planned manifest uses:

```text
schema: hasna.service_contract.v2
contractVersion: v2
```

`service_contract.v2` MUST:

- preserve the existing package identity, class, bins, deployment modes,
  storage, lifecycle, and conformance concepts;
- model an explicit API base path that supports `/vN` and same-origin
  `/api/vN` without ambiguous route rewriting;
- keep `/health`, `/ready`, `/version`, and `/openapi.json` outside the product
  API base path;
- reference the canonical operation registry and generated schema snapshot;
- declare API, SDK, CLI, MCP, UI, worker, and provider surfaces from the same
  operation source;
- declare auth modes, permissions, entity boundaries, and negative tests;
- declare idempotency, ETag, request ID, pagination, filtering, deprecation,
  and error-envelope policies;
- declare worker queues, leases, retries, dead letters, approvals, provider
  modes, reconciliation, and readiness gates;
- declare package, installed-artifact, schema-drift, parity, auth-negative,
  no-secret, and evidence-bundle smokes;
- distinguish `local`, `self_hosted`, and `cloud` deployment modes from the
  package's `local | cloud` runtime storage vocabulary.

The implementation MUST keep v1 exports and validation available. It MUST ship
an explicit v1-to-v2 adapter where semantics are known, compatibility fixtures,
and a report of fields that require an owner decision. It MUST NOT rewrite a v1
manifest in place or claim that a lossy v2-to-v1 conversion is safe.

## 9. Event envelope, audit, and evidence

### 9.1 Deployment event envelope

Deployment owns domain event meanings. OpenEvents owns durable channels,
delivery, replay, and subscriber mechanics. The existing comms event envelope
is not a substitute for a durable deployment-domain event.

`DeploymentEventEnvelope` MUST include:

- event ID and namespaced type such as
  `deployment.plan.issued`, `deployment.decision.approved`,
  `deployment.plan.superseded`, `deployment.attempt.started`, or
  `deployment.receipt.issued`;
- event schema version;
- occurred-at timestamp;
- producer `ActorRef` or actor pointer;
- aggregate ID, aggregate schema, and aggregate revision;
- product, environment, plan, and attempt references as applicable;
- correlation, causation, request, and trace IDs;
- per-aggregate sequence number;
- dedupe key;
- typed payload schema and payload;
- redaction profile;
- `EvidenceRef` pointers when the event asserts observed or verified facts.

Events are emitted through the transactional outbox in the same database
transaction as the aggregate change. Consumers deduplicate by event ID and
dedupe key. Replay MUST preserve the original event identity and occurrence
time.

### 9.2 Audit

Every read of sensitive metadata, authorization decision, mutation,
provider-side operation, reconciliation, override, cancellation, and evidence
access MUST create a redacted audit event containing:

- actor, role, account, and machine references where available;
- operation registry ID and version;
- target resource and revision;
- authorization and policy decision;
- request, trace, idempotency, and provider correlation references;
- before and after digests for mutable state;
- outcome, reason code, and evidence references;
- redaction state and timestamp.

Audit is append-only. Audit data MUST NOT contain credentials, secret values,
raw provider payloads, arbitrary callback bodies, or Terraform state.

### 9.3 Evidence profile

Deployment reuses `EvidenceRef`. For evidence that authorizes or proves a
deployment step, the deployment profile MUST require:

- immutable URI or content-addressed artifact location;
- SHA-256 digest;
- content type;
- producer actor;
- creation timestamp;
- redaction state;
- subject resource references;
- retention or expiry class where relevant.

Live observations that cannot be content-addressed directly MUST store a
sanitized captured artifact and point the `EvidenceRef` to that artifact.
Launch evidence MUST refer to immutable evidence, not mutable dashboard views.

## 10. Compatibility and evolution

### 10.1 Schema evolution

- Schema identifiers are immutable.
- Breaking field or semantic changes require a new schema major.
- Additive optional fields MAY be introduced compatibly when old readers can
  ignore them safely.
- New required fields require a new major or an explicit migration phase.
- Enums MUST define how unknown future values are handled; security-sensitive
  enums fail closed.
- Producers MUST record the contract-kit version used to validate and
  canonicalize a digest-bound record.
- Consumers MUST reject unsupported major versions before planning or
  execution.

### 10.2 Dual-read migration

Adopters MAY dual-read old and new records during migration. New writers MUST
not emit v2 until all required readers, validators, and rollback tooling are
proven. Dual-write is allowed only as an explicitly bounded shadow mechanism
with one authoritative writer and comparison evidence.

An issued plan is always interpreted with its pinned schema and registry
versions. A package upgrade MUST NOT reinterpret an old plan under new
operation semantics.

### 10.3 Legacy surface retirement

Legacy deploy, promote, rollback, destroy, blueprint-apply, raw-secret, and
arbitrary-hook routes are not compatibility requirements. They remain disabled
or internal while replacement operations are adopted. Retirement proceeds
through deprecation evidence and ends with an explicit `410 Gone`; a missing
route or silent behavioral change is not a migration plan.

## 11. Conformance requirements for future implementation

The future schema implementation is incomplete unless it adds:

- Zod schemas and exported TypeScript input/output types;
- schema IDs and embedded-contract registry mappings;
- generated or checked JSON Schemas;
- valid fixtures for every planned record;
- adversarial fixtures for shell, environment-map, raw-state, secret,
  provider-ID, stale-revision, and digest-substitution attacks;
- `validateDeploymentContractSet` or an equivalent complete-graph validator;
- semantic DAG, cycle, reference, digest, and capability tests;
- v1/v2 service-contract compatibility fixtures and adapters;
- operation-registry parity tests;
- idempotency, ETag, compare-and-swap, fencing, replay, and event-order tests;
- package build, declaration, packed-artifact, and installed-artifact tests;
- secret-output scans over fixtures, validation errors, CLI, MCP, API, SDK,
  events, audit, and evidence output.

Static schema conformance is not deployment success. Provider, infrastructure,
migration, restore, alarm, promotion, and rollback claims require separate live
evidence in their owning systems.

## 12. Adoption and rollback

Adoption is phased and fail-closed.

### Phase 0: documentation and ownership

- Land this execution-free contract.
- Reconcile ownership with Projects, app repositories, Factory, Deployment,
  Billing or Economy, provider adapters, OpenEvents, and infrastructure owners.
- Make no schema or runtime implementation claim from this phase.

Rollback: revert or supersede the document. No runtime or data rollback is
needed because this phase has no executable effect.

### Phase 1: contract implementation

- Add the planned schemas, service-contract v2, registry contract, validators,
  fixtures, exports, adapters, and packed-artifact checks.
- Preserve every v1 export.
- Run independent adversarial review before release.

Rollback: stop v2 publication, keep v2 data readable, restore the prior package
release, and retain v1 validation. Do not delete already issued v2 records.

### Phase 2: shadow producers and dual readers

- Emit new records beside the current system without authorizing provider
  mutation.
- Compare projections, intent, artifacts, plans, and evidence.
- Prove deterministic digests and compatibility.

Rollback: disable new producers, continue reading preserved records for audit,
and return consumers to v1 or legacy read paths. The previous authoritative
writer remains unchanged.

### Phase 3: plan-only control plane

- Enable the operation registry, authorization checks, plan compiler, and
  read-only provider observations.
- Produce plans, decisions, events, and evidence without execution.
- Prove idempotency, concurrency, fencing, replay, and reconciliation in
  non-mutating tests.

Rollback: disable attempt creation, preserve plans as non-executable evidence,
and keep legacy mutations disabled rather than silently routing around the
control plane.

### Phase 4: non-critical canary

- Enable one bounded, approved provider mutation against one non-critical
  environment.
- Require sandbox proof, exact artifact digest, rollback target, restore point,
  alarms, reconciliation, and independent review.
- Execute rollback as a new plan and capture receipts.

Rollback: stop new attempts, fence active workers, reconcile unknown outcomes,
and execute the approved rollback plan. Never use an ad hoc shell or direct
provider mutation as the contract rollback path.

### Phase 5: fleet adoption

- Build the Projects-derived capability census.
- Roll out in measured waves with abort thresholds.
- Require launch evidence and rollback drills per wave.
- Retire legacy routes only after supported consumers migrate.

Rollback: halt later waves, keep completed receipts immutable, return affected
environments through new rollback plans, and preserve dual-read compatibility
until all consumers are stable.

## 13. Raw-session provenance

This design is sourced from the raw top-level Codewith session JSONL, not from
its compacted summary.

Session ID:
`019f8f76-fb12-7330-a863-1a51f6967d6d`

Raw session:
`/home/hasna/.codewith/sessions/2026/07/23/rollout-2026-07-23T17-52-47-019f8f76-fb12-7330-a863-1a51f6967d6d.jsonl`

This absolute JSONL path is a current-machine locator only, not a portable
durable identifier. Before using it, validate the top-level `session_meta`
fields: `id` is `019f8f76-fb12-7330-a863-1a51f6967d6d`, `cwd` is
`/home/hasna/workspace/hasnaxyz/internalapp/iapp-deployment`, `source` is
`cli`, and `thread_source` is `user`.

The JSONL is append-only and may grow. Provenance MUST never be anchored to a
whole-file hash. The stable evidence is each bounded `response_item` JSONL
line, role, phase, exact opening, and message-scoped digest below.

| JSONL line | Role | Phase | Opening | Pre-citation SHA-256 |
| --- | --- | --- | --- | --- |
| 1766 | `assistant` | `final_answer` | “The right end state is a private, self-hosted deployment control plane for every Hasna app.” | `ecdaccd46404a0cc92a8a03571e2925ceab361c8cc15088a3946692148f84b01` |
| 1774 | `user` | `not present` | “ok now what is the next step for this say we want to implement this plan, where do we write it down, what should be the procedure for this” | `7fe072332ab54a0fb03161b76b0f393b1e1ac59bd224fff953f4fbcd9a9dd904` |
| 1844 | `assistant` | `final_answer` | “The next step is not code yet. It is to bootstrap a new implementation program from the completed blueprint.” | `a089fcc9b0ae2853ddb3007176f995bb09c167252d79858e07da6b0749991f16` |

Each assistant digest is SHA-256 over the parsed `output_text` before the first
`<oai-mem-citation>` marker, including the newline immediately before that
marker. The user digest is SHA-256 over that response item's parsed
`input_text`; it has no citation marker. No whole-file hash is used because the
session file is append-only and may grow while the cited records remain
unchanged.

The compacted summary was used only to locate the raw records. It is not a
normative source for this contract.
