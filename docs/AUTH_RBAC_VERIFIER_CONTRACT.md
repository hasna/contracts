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
mode. Default tenant, workspace, or entity ids are not accepted on any shared
or server-backed deployment.

## Token Types

| Type | Intended use | Must not authorize |
| --- | --- | --- |
| Human session | Dashboard/browser human interaction. | Provider webhooks, unattended worker jobs, broad service administration. |
| API key | External automation or SDK access. | Human dashboard session, provider webhooks, credential export, destructive action without approval. |
| Service token | Service-to-service calls. | Human-only approvals, browser session mutation, provider action without declared service capability. |
| MCP token | Agent tool calls. | Broad admin by default, credential value reads, live provider side effects without approval. |
| Machine/job token | Worker, queue, and machine-local jobs. | Human session, arbitrary workspace access, provider mutation outside job scope. |
| Provider webhook | Inbound provider callback. | Any caller-initiated API, dashboard, CLI, or MCP operation. |
| Local-dev | Loopback-only local development. | Non-loopback bind, shared data, server-backed claims. |

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

## Tenant Identifier

`AuthContext.tenantId` above is a required boundary claim, but until now no
Hasna token had a place to carry it. The API-key claim set
(`ApiKeyClaims` in `@hasna/contracts/auth`) now carries an **optional `tid`**,
and this section is the normative definition every Hasna auth seam binds to.

**Wire type.** A tenant id is **always a JSON string**. Never a number, never an
object, never `null`. A store with a PostgreSQL `uuid` column serializes its
canonical string form; a store with a `text` column passes its value through.
This is the fix for the observed drift where the same logical tenant was a
`uuid` in one repo's schema and `text` in another's, so neither could resolve
the other's identifier.

**Grammar.** `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, maximum 64 characters
(`TENANT_ID_PATTERN`, `MAX_TENANT_ID_LENGTH`). Deliberately permissive about
shape — a UUID, a ULID, a slug (`acme-corp`) and a prefixed id
(`org_01HQ…`) are all valid, because all four are already in use — and strict
about character set: whitespace, control characters, `/`, `:` (reserved as the
scope separator), `@`, quotes and non-ASCII are excluded, so a tenant id is
always safe in a log line, a header value, and a URL path segment.

**Comparison.** Tenant ids are **opaque and case-sensitive**, with exactly one
exception: **UUIDs**. A PostgreSQL `uuid` column does not store what you gave
it — it parses and rewrites it, so `9D4B2A1C0E5F4A7B8C3D1E2F3A4B5C6D`,
`{9d4b2a1c-…}` and `9D4B2A1C-…` all come back as one canonical lowercase
hyphenated string, while a `text` column does no such thing. That asymmetry, not
letter case in the abstract, is the mechanism behind the drift, so
`canonicalizeTenantId` folds **exactly the spellings a `uuid` column accepts**
(hyphenated, hyphen-less, and either wrapped in braces, in any case) to the
canonical form, and folds nothing else. Both sides are trimmed before
comparison. Issuers MUST emit the canonical form; `mintApiKey` and
`ApiKeyStore.insert` do it for the caller.

**Two things this rule deliberately does NOT do.**

- **ULIDs are not case-folded**, even though Crockford base32 is a
  case-insensitive encoding. No database type silently rewrites a ULID the way
  `uuid` rewrites a UUID, so folding would only create new ways for two distinct
  opaque ids to collide. Issuers MUST emit the canonical uppercase form. The
  same applies to prefixed ids such as `org_01HQ…`.
- **It does not accommodate a store that treats two spellings of one UUID as two
  tenants.** Under this contract they are one tenant. If a `text` column holds
  both, that is a data-modelling bug; accommodating it would mean not closing the
  drift at all.

**Absence is not a wildcard.** A token with no `tid` is *untenanted* — it names
no organization. A service whose rows carry an organization reference MUST
reject it rather than treat it as "all tenants". Set `requireTenant: true` on
`verifyApiKey` / `verifyApiKeyToken` to get that rejection from the kit;
`expectedTid` implies it. Any truthy `requireTenant` enables the gate — a
security control must not fail open because a config value arrived as the string
`"true"`. Both tenant denials return **403**, not 401: the credential is
authentic and unexpired, it is simply not permitted for this organization — the
same shape as `insufficient_scope`.

**Absence must be read as absence.** Because the untenanted case is
load-bearing, `tid` MUST be read as an **own property** (`ownTenantId`) wherever
it is consumed — parse, verify, mint, and persist alike. A plain `claims.tid`
resolves through the prototype chain, so one `Object.prototype.tid` write
anywhere in the process would hand every untenanted token a tenant, and one that
skipped validation precisely because the claim was absent. For the same reason a
tenant FILTER is applied on presence, not truthiness: `ApiKeyStore.list({ tid })`
throws on an empty or ungrammatical `tid` rather than dropping the clause and
widening the query to every organization's records.

**A per-call tenant narrows; it never replaces.** When a service is pinned with
`verifyApiKey({ expectedTid })` *and* a route supplies
`context.expectedTid` (typically from `/v1/orgs/:tid/…`), the two MUST agree.
Letting the per-call value win would let any holder of a valid token for the app
— they all verify against the same signing secret — defeat the pin by addressing
their own organization in the URL.

**Tamper evidence.** `tid` lives inside the signed claim body, so altering it
invalidates the signature. It is not a header and MUST NOT be read from one.

**Compatibility.** The claim is additive. A token minted before `tid` existed
parses, verifies, and authenticates unchanged, and minting without a tenant
produces a byte-identical claim body — so stored `tokenHash` values still match.

## Identity Seam (offline EdDSA fleet tokens)

Every server-bearing repo MUST keep a **complete in-repo API-key default** — the
HMAC path above — and MAY additionally expose an **identity option**: verify
EdDSA tokens minted by a configured issuer against a configured JWKS, and map
the token's `tid` onto one of the server's own organizations.

`open-tenants` is the **reference issuer behind this seam, never a dependency**.
Nothing in `@hasna/contracts` imports it, and a repo that never configures the
identity option is fully runnable on its own — which is what R2 and R3 require.

### Offline verification is structural, not a promise

Downstream services MUST NOT call back to the IdP on the request path.
`verifyFleetToken` therefore takes a **key set value**, never a URI, and
`@hasna/contracts/auth`'s identity module contains no network primitive at all
(asserted by `tests/auth-identity.test.ts`). `HASNA_<NAME>_IDENTITY_JWKS_URI` is
**recorded configuration only** — refreshing the key set is the operator's job,
out of band. `HASNA_<NAME>_IDENTITY_JWKS` (inline JWKS JSON) needs no refresher
at all.

### Wire shape

This is the shape `open-tenants` already mints — standardized here, not invented.

Header: `{ "alg": "EdDSA", "kid": "<key id>", "typ": "at+jwt" }`

| Claim | Required | Meaning |
| --- | --- | --- |
| `iss` | yes | Issuer. An opaque wire-contract string, **not necessarily a URL**. |
| `aud` | yes | The app slug the token is for. A JWT array form is accepted. |
| `sub` | yes | Principal id in the issuer's namespace. |
| `tid` | yes | Tenant — see **Tenant Identifier**. Same grammar as the API-key claim. |
| `pt` | yes | `user` or `service`. |
| `scope` | yes | Array, in the same `<app>:<action>` grammar as API-key scopes. |
| `iat` | yes | Issued-at, epoch seconds. |
| `exp` | yes | Expiry, epoch seconds. |
| `nbf` | no | Not-before, epoch seconds. |
| `jti` | yes | Token id — the only handle a revocation list can key on. |

Unlike the API-key claim, **`tid` is REQUIRED here**. The API-key claim is
optional because it had to be added additively to a live token format; the
identity seam is new and is tenant-native from its first token.

### Mandatory checks

A conforming verifier MUST reject a token when any of these fails. Each exists
because its absence is a known, exploitable weakness:

- `alg` is not exactly `EdDSA`, checked **before any key is selected** — this is
  what defeats `alg: "none"` and every algorithm-confusion variant.
- `typ`, when present, is not `at+jwt`. A header that OMITS `typ` still
  verifies — the reference issuer always stamps it, and rejecting its absence
  would break any other conforming issuer.
- the header carries `crit` or `b64` (RFC 7515 s4.1.11 / RFC 7797): this
  verifier implements no extensions, so a header the issuer marked
  must-understand is a rejection, never something to ignore.
- the header carries no `kid`, or no configured key matches it.
- **the configured key set is empty or has no usable Ed25519 key.** An empty key
  set MUST fail. A verifier that passes when it has nothing to check protects
  nothing.
- the JWKS carries private material (a `d` component). That is an incident, not
  a usable key.
- the signature does not verify.
- `iss` is not the configured issuer.
- **`aud` is not the configured audience.** The audience check is never
  optional: an optional audience check means a token minted for one app is
  accepted by every other app.
- **`exp` is missing or non-numeric.** A missing `exp` MUST be a rejection,
  never a skipped check — skipping it turns an absent claim into an immortal
  token.
- `exp - iat` exceeds **24h**. Offline verification cannot see a revocation, so
  the TTL *is* the revocation window.
- `exp`/`nbf`/`iat` fail against the clock, within the configured leeway. Leeway
  is itself capped at **300s** and clamped at verification time: it extends the
  window in which an expired — and possibly revoked — token is still accepted,
  so an unbounded value silently undoes the TTL ceiling above. One env-var typo
  (`300000` for `300`) would otherwise buy three and a half days of it.
- `sub` or `jti` are absent, or exceed 255 printable-ASCII characters. `jti` is
  handed to the operator's revocation lookup, which is a database key in every
  realistic implementation.
- `tid`, `pt`, `scope`, `sub`, or `jti` are missing or malformed.

Tenant is checked **before** scopes, so a wrong-organization token is never
reported as merely under-scoped.

### The token string is not an identity — never key anything on it

`Buffer.from(sig, "base64url")` accepts trailing `=` padding and standard-base64
`+`/`/`, so **many distinct token strings decode to the same signature and
authenticate as the same principal.** That is harmless here: the signature is
what is checked and `jti` is the revocation handle.

It is NOT harmless for a relying party that denylists, rate-limits, caches, or
deduplicates on the raw token string — every such control is bypassed by
appending a `=`. Key those on `jti`, never on the token text.

### Revocation — a known gap, stated rather than hidden

Offline verification cannot observe a revocation, and the reference issuer has
no fleet-wide revocation today: a revoked token stays acceptable for the
remainder of its (≤24h) life. The contract therefore **requires `jti`**, so
revocation is at least possible, and `createIdentityVerifier` accepts the same
optional `isRevoked` hook shape as the API-key middleware — keyed by `jti`
instead of `kid`. A service needing prompt revocation supplies it.

### `tid` -> org

The token names a tenant in the **issuer's** namespace; the service resolves it
to one of its **own** organization rows (`resolveTenantOrg`). A resolver
returning `null` MUST deny. A service that invents an organization on an unknown
`tid` has no isolation boundary at all.

### Configuration

| Env key | Meaning |
| --- | --- |
| `HASNA_<NAME>_IDENTITY_ISSUER` | Expected `iss`. **No default.** |
| `HASNA_<NAME>_IDENTITY_AUDIENCE` | Expected `aud`. Defaults to the app name. |
| `HASNA_<NAME>_IDENTITY_JWKS_URI` | Where the operator's own refresher fetches keys. Recorded only. |
| `HASNA_<NAME>_IDENTITY_JWKS` | Inline JWKS JSON — the fully-offline option. |
| `HASNA_<NAME>_IDENTITY_LEEWAY_SECONDS` | Clock-skew leeway. Default 0. |

Each key also has the `<NAME>_*` alias form, matching `storageEnvKeys`.

Three outcomes, and the middle one is the point:

- **nothing set** -> the option is disabled and the server runs on its in-repo
  API-key default. There is deliberately **no default issuer and no default JWKS
  URI** (R1).
- **partially set** -> an **error naming the missing variable**. A
  half-configured identity option MUST NOT silently degrade to "API keys only":
  an operator who set an issuer believes tokens are being checked.
- **fully set** -> enabled.

A configured `HASNA_<NAME>_IDENTITY_JWKS_URI` must be `https`, or `http` on an
exact loopback host, with no embedded credentials, whitespace, or control
characters.

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
appropriate to the deployment. Dashboard APIs must not accept MCP or
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
