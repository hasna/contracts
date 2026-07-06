# Auth And RBAC Verifier Contract

This contract defines the shared verifier model for built `open-*` and `iapp-*`
server, MCP, CLI-token, API-key, dashboard, worker, and provider webhook
surfaces.

It extends the existing `@hasna/contracts/auth` API-key kit. App adoption may
use that kit directly or bridge another session/token provider into the same
auth context and negative-test matrix.

## Scope

First adoption targets:

- `iapp-access`
- `open-feedback`
- `open-telephony`
- `open-contacts`
- `open-calendar`
- `iapp-data`

Broader affected packages include finance, customer-data, file/search,
infra-control, and multi-tenant iapps that expose HTTP, MCP, dashboard, worker,
sync, export, provider, or destructive-action surfaces.

Excluded:

- Public static assets.
- Explicit local-only loopback development routes with no stored user,
  business, finance, provider, credential, file, note, report, or org data.
- CLI-only commands that operate solely on an isolated user-selected local file
  and declare that exception in their route/tool inventory.

## Auth Context

Every protected operation produces an `AuthContext` before domain code runs.
Domain code must not parse tokens directly.

Required fields:

| Field | Meaning |
| --- | --- |
| `actor.kind` | `human`, `service`, `mcp-agent`, `worker`, `machine`, `provider-webhook`, or `system`. |
| `actor.id` | Stable actor id or hashed external principal. |
| `auth.method` | `session`, `api-key`, `service-token`, `mcp-token`, `machine-token`, `job-token`, `provider-webhook`, or `local-dev`. |
| `token.idHash` | Hash of token/session/key id, never the token value. |
| `token.scopes` | Normalized scopes using `<app>:<action>` grammar. |
| `token.expiresAt` | Expiry timestamp or explicit non-expiring policy reason. |
| `tenantId` | Tenant/org id when the app supports shared or deployed mode. |
| `workspaceId` | Workspace/project id where applicable. |
| `entityId` | Company/legal/entity id where applicable. |
| `dataOwnerId` | Owner/user id for personal data where applicable. |
| `roles` | Normalized roles assigned within the boundary. |
| `providerAccountId` | Provider account id for webhooks or provider actions. |
| `requestId` | Request id carried across API, MCP, CLI, SDK, dashboard, and worker logs. |

Missing boundary claims fail closed outside explicitly documented local-only
mode. Default tenant, workspace, or entity ids are not accepted in shared,
self-hosted, or cloud modes.

## Token Types

| Type | Intended use | Must not authorize |
| --- | --- | --- |
| Human session | Dashboard/browser human interaction. | Provider webhooks, unattended worker jobs, broad service administration. |
| API key | External automation or SDK access. | Human dashboard session, provider webhooks, credential export, destructive action without approval. |
| Service token | Service-to-service calls. | Human-only approvals, browser session mutation, provider action without declared service capability. |
| MCP token | Agent tool calls. | Broad admin by default, credential value reads, live provider side effects without approval. |
| Machine/job token | Worker, queue, and machine-local jobs. | Human session, arbitrary workspace access, provider mutation outside job scope. |
| Provider webhook | Inbound provider callback. | Any caller-initiated API, dashboard, CLI, or MCP operation. |
| Local-dev | Loopback-only local development. | Non-loopback bind, shared data, self-hosted/cloud claims. |

Every verifier returns an audit event for both allow and deny decisions.

## Scope Grammar

Use the existing `<app>:<action>` grammar from `@hasna/contracts/auth`.

Required scopes are concrete, for example:

- `<app>:read`
- `<app>:write`
- `<app>:export`
- `<app>:import`
- `<app>:delete`
- `<app>:approve`
- `<app>:revoke`
- `<app>:credential.read`
- `<app>:credential.rotate`
- `<app>:provider.read`
- `<app>:provider.execute`
- `<app>:admin`

Granted wildcards such as `<app>:*`, `*:read`, and `*` are allowed only for
explicit admin/service bootstrap cases and must be visible in audit output as
high-risk grants.

## Role Model

Apps may add domain roles, but the shared minimum role set is:

| Role | Use |
| --- | --- |
| `admin` | Tenant/workspace administration. |
| `operator` | Queue, provider, incident, and operational review. |
| `member` | Normal authenticated app use. |
| `readonly` | Read-only access. |
| `billing` | Billing, invoices, subscriptions, payment-method administration. |
| `finance` | Accounting, banking, treasury, payroll, and money movement review. |
| `reviewer` | Human review without execution authority. |
| `approver` | Approval authority for destructive/provider/money/legal actions. |
| `service` | Service-to-service automation. |
| `worker` | Background worker/job execution. |

RBAC checks combine role, scope, boundary, token type, and operation risk class.
A matching scope alone is not enough for high-risk actions.

## Operation Inventory

Each server route, MCP tool, CLI JSON operation, SDK method, dashboard route,
worker action, sync/export path, and provider callback must be inventoried.

Inventory fields:

- Operation id.
- Surface: API, MCP, CLI, SDK, dashboard, worker, webhook.
- Method/path/tool/command/function.
- Auth method.
- Required scopes.
- Required roles.
- Required boundary claims.
- Risk class.
- Audit event type.
- Idempotency requirement.
- Public/local-only exception, if any.

Route/tool inventory must fail CI when a protected operation lacks auth,
boundary, or audit metadata.

## Boundary Rules

Every query and mutation carries a boundary predicate before data access:

- Tenant/org for shared deployments.
- Workspace/project for project-scoped systems.
- Entity/company for finance, legal, workforce, and sourcing domains.
- Data owner for personal notes, files, contacts, calendars, recordings,
  reports, analytics, and profile data.
- Provider account for webhooks and provider actions.
- Machine id for fleet, server, sandbox, terminal, browser, computer, and
  machine-local operations.

Fixtures must include at least two tenants/workspaces/entities with overlapping
object ids. Tests must prove overlapping ids cannot bypass predicates across
API, MCP, CLI, SDK, dashboard, worker, sync, export, and webhook paths.

## Negative Test Matrix

Every adopting repo must cover:

| Case | Expected result |
| --- | --- |
| Unauthenticated | 401 or equivalent auth failure. |
| Expired token/session | 401 and audit deny. |
| Revoked token/key | 401 and audit deny. |
| Disabled token/key | 401 and audit deny. |
| Wrong token type | 403 and audit deny. |
| Missing scope | 403 and audit deny. |
| Read token attempts mutation | 403 and audit deny. |
| Wrong role | 403 and audit deny. |
| Wrong tenant/workspace/entity | 404 or 403 without leaking object existence. |
| Missing boundary claim | 403 outside explicit local-only mode. |
| Service token on human route | 403. |
| MCP token on admin/destructive route | 403 unless scoped and approved. |
| Local-dev token on non-loopback bind | Startup or request failure. |
| Provider webhook wrong signature | 401/403 and replay/audit record. |
| Provider webhook replay | 409 or ignored duplicate with audit record. |
| Provider webhook stale timestamp | 401/403 and audit deny. |

Error responses and logs must not contain token values, credential values, raw
provider signatures, private payloads, or cross-tenant object details.

## Dashboard Requirements

Human dashboard sessions must use secure cookies, CSRF/origin protection,
logout invalidation, refresh/rotation semantics, and same-site policy
appropriate to the deployment mode. Dashboard APIs must not accept MCP or
service tokens unless explicitly documented for a non-browser operator action.

## MCP And CLI Requirements

MCP tools and CLI JSON commands must use least-privilege scopes. Agent tokens
must not inherit broad human-admin permissions by default.

CLI commands that print auth diagnostics must print token status, hash/kid,
scope names, expiry, and revocation state only. They must never print token
values after first issue.

## Provider Webhooks

Provider webhooks use provider-specific signature verification, timestamp
tolerance, replay/idempotency storage, payload-size limits, expected provider
account binding, and auditable failure modes before parsing side effects.

Webhook auth context uses `actor.kind = provider-webhook` and must not be reused
for user-initiated API or MCP operations.

## Audit Requirements

Every allow and deny auth decision emits a safe audit event with:

- Request id.
- Operation id.
- Actor kind and id.
- Auth method.
- Token id hash/kid.
- Scopes and roles.
- Boundary claims.
- Decision: allow or deny.
- Deny reason.
- Risk class.
- Provider account id when applicable.
- Redaction level.

Audit events must be append-only in shared/deployed modes and exportable as
redacted evidence.

## Adoption Checklist

- Add operation inventory for API, MCP, CLI, SDK, dashboard, worker, sync,
  export, and webhook surfaces.
- Normalize all verifiers to produce `AuthContext`.
- Add auth mode and scope metadata to OpenAPI or route schema.
- Add RBAC role matrix.
- Add boundary predicates for every query and mutation.
- Add overlapping-id multi-tenant fixtures.
- Add negative matrix tests.
- Add provider webhook signature/replay tests when applicable.
- Add no-secret output scan over auth failures, CLI JSON, MCP output, API
  responses, dashboard payloads, logs, snapshots, and audit exports.
- Add audit allow/deny event tests.

## First Adoption Notes

- `iapp-access`: should issue and verify shared access tokens, revocation
  events, review state, and offboarding fanout.
- `open-feedback`: split submit/read/export scopes and fail closed for
  non-local reads/mutations.
- `open-telephony`: require API auth, Twilio signature/replay checks, and
  provider-action approval gates.
- `open-contacts`: enforce export/document controls, tenant/entity predicates,
  and merge/rollback operator roles.
- `open-calendar`: enforce calendar roles on sampled routes and provider sync.
- `iapp-data`: enforce tenant isolation, backup/export/import privileges, and
  PII redaction roles.

## Reviewer Mapping

This contract covers:

- `SEC-DATA-01`: shared human session and API token semantics.
- `SEC-DATA-02`: RBAC, tenant, workspace, and entity boundaries.
- Service baseline `SVC-08`: auth, scope, and negative API tests.
- Provider webhook portions of `SEC-DATA-04`.
- Audit identity requirements that feed `SEC-DATA-05`.
