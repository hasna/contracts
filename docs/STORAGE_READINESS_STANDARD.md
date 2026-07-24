# Durable Storage Readiness Standard

This standard defines the minimum durable-storage evidence required before a
built `open-*` or `iapp-*` package can claim shared, self-hosted, cloud,
provider-live, finance, or production readiness.

Static source presence is not enough. Each supported data mode must have
runtime evidence.

## Deployment Mode Mapping

| Deployment mode | Source of truth | Required proof |
| --- | --- | --- |
| `local` | Local SQLite or local files on the operator machine. | Isolated data-dir smoke, migration/schema version check, backup/export path, local delete behavior. |
| `self-hosted` | Hasna-owned AWS service stack for internal apps, or app-owned Postgres/S3 in the declared self-hosted contract for OSS packages. | Postgres migrations, readiness, TLS, backup/restore, RLS/boundary checks when shared, and operator runbook. |
| `cloud` | Managed multi-tenant SaaS service. | All self-hosted proofs plus tenant isolation, RLS, PITR/restore evidence, retention/export/delete, support/audit access, and live provider reconciliation where applicable. |

`remote` is not a deployment mode. It only means the runtime is on another
machine. Do not use `remote` to make readiness claims.

## Source Of Truth Declaration

Every repo must declare:

- Supported modes: `local`, `self-hosted`, `cloud`, or explicit unsupported
  reason per mode.
- Authoritative store per mode.
- Derived stores and caches.
- Object/blob stores and ownership rules.
- Search indexes and rebuild rules.
- Queue/outbox tables.
- Audit/evidence ledgers.
- Provider reconciliation records.
- Migration owner.
- Restore owner.

If a local cache exists in a shared/deployed mode, the contract must say whether
it is disposable, write-through, read-through, or migration-only. A cache cannot
silently become source of truth.

## Postgres Readiness

Postgres-backed modes require:

- Fresh-database migration test.
- Migration ledger with checksums.
- Drift detection for edited historical migrations.
- Backwards/forwards compatibility policy.
- Readiness probe that distinguishes unreachable database, unapplied
  migrations, checksum drift, wrong schema version, wrong tenant, and TLS
  misconfiguration.
- Transaction boundaries for each domain write.
- Idempotency key storage for retried mutations.
- Durable outbox for provider or cross-app side effects.
- Connection TLS policy and credential-source policy.

## RLS And Boundary Enforcement

Multi-tenant, multi-workspace, multi-entity, or multi-owner Postgres databases
must use storage-level boundary enforcement where practical.

Required evidence:

- Two-tenant/workspace/entity fixture with overlapping object ids.
- Direct DB-session negative tests for cross-boundary reads and writes.
- App-level API/MCP/CLI/worker negative tests for the same fixture.
- Migration tests that create and preserve RLS policies.
- Admin/service-account exceptions documented with audit events.

If RLS is not used, the repo must document why and provide equivalent negative
tests for every data path.

## Backup And Restore

Every durable mode must define:

- Backup command or service.
- Restore command or process.
- Scope: full app, tenant, workspace, entity, project, or user.
- Object store inclusion.
- Search/index rebuild behavior.
- Audit/evidence preservation.
- Encryption and credential handling.
- Restore verification checksum or row-count assertions.

Validation must include a backup/restore smoke with fixture data and a checksum
or deterministic query result after restore.

## Retention, Export, Delete, And Tombstones

Repos storing user, business, finance, provider, file, note, report, calendar,
contact, analytics, recording, transcript, or profile data must define:

- Default retention period.
- Legal hold behavior.
- Export format and authorization.
- Delete behavior.
- Tombstone shape.
- Propagation to derived stores, indexes, caches, search documents, dashboards,
  exports, sync peers, object stores, and provider mirrors.
- Redacted preview rules for evidence display.

Deletes must be tested against primary store, derived store, and export/sync
surfaces. Shared/deployed modes must not rely on best-effort local cleanup.

## Conflict Handling

Local-first or sync-capable apps must define:

- Conflict key.
- Revision/version field.
- Tombstone precedence.
- Clock skew behavior.
- Interrupted sync recovery.
- Sensitive-table behavior.
- Merge policy or explicit no-merge/fail-closed policy.
- Operator conflict review surface.

If a repo does not support sync, the contract must say so and tests must prove
there is no hidden sync/cache mode.

## TLS And Credential Posture

Postgres and object-store access must use:

- TLS verification appropriate to the provider.
- No custom insecure TLS override in production/shared modes.
- Secret references instead of raw credential values in config, logs, CLI,
  MCP, API responses, dashboards, reports, and evidence bundles.
- Rotation and revocation plan.
- Readiness failure when required credential references are missing.

Diagnostics may include secret reference names and hashes, but never credential
values.

## Finance And Provider Stores

Finance, billing, payments, banking, payroll, treasury, wallet, provider-send,
telephony, mail, signing, legal, domain, deploy, and shopping systems also
require:

- Immutable posted-record policy.
- Transactional outbox.
- Idempotency/replay table.
- Approval ledger.
- Provider request/response evidence with secret redaction.
- Reconciliation table.
- Rollback/remediation records.
- Emergency freeze/disable state where applicable.

Money movement, provider sends/calls, DNS/domain mutation, signing, filings,
orders, and deployments must not be considered ready without reconciliation
evidence.

## Readiness Checklist

- Mode declaration uses `local`, `self-hosted`, and `cloud` correctly.
- Source of truth is declared for each mode.
- Derived stores and caches are declared.
- Fresh-database migration test passes.
- Migration drift/checksum test passes.
- Readiness probe distinguishes migration, TLS, credential, drift, and boundary
  failures.
- RLS or equivalent boundary enforcement is tested.
- Backup/restore smoke passes.
- Retention/export/delete/tombstone tests pass.
- Conflict/sync behavior is defined and tested or explicitly unsupported.
- TLS and credential posture tests pass.
- Secret/no-token output scan passes for storage diagnostics.
- Provider/finance outbox, idempotency, approval, audit, and reconciliation
  records exist where applicable.
- Evidence bundle records command, package version, git head, mode, data dir or
  redacted storage ref, output hash, and verifier result.

## First Adoption Apps

| Domain | First apps | Required emphasis |
| --- | --- | --- |
| Data/project | `open-knowledge`, `open-mementos`, `open-projects`, `open-todos`, `open-files` | Local/source drift, migrations, backup/restore, export/delete, sync conflicts, redaction. |
| Finance | `open-banking`, `open-accounting`, `iapp-accounting`, `iapp-payments`, `iapp-billing`, `iapp-treasury`, `iapp-wallets`, `iapp-payroll` | Postgres transactions, outbox, idempotency, immutable posted records, reconciliation, approvals. |
| Comms/customer | `open-mailery`, `open-telephony`, `open-feedback`, `open-contacts`, `open-calendar`, `open-tickets` | Provider event storage, retention/export/delete, webhooks, tenant/entity boundaries. |
| Infra/control | `open-backup`, `open-deployment`, `open-domains`, `open-gateway`, `open-machines`, `open-sandboxes`, `open-secrets` | Credential references, RLS where shared, backup restore, operator readiness, deployment-state audit. |
| Iapp data/org | `iapp-data`, `iapp-access`, `iapp-controls`, `iapp-workforce`, `iapp-companies`, `iapp-entities` | Tenant/entity boundaries, access review durability, offboarding fanout, audit export. |

## Reviewer Mapping

This standard covers:

- `SEC-DATA-03`: durable stores, RLS, migration drift, backup/restore, and
  tombstones.
- Storage portions of reviewer-11 provider/deploy readiness tasks.
- Finance/data shard requirements for source-of-truth declarations, durable
  repositories, outbox/idempotency, and reconciliation.
- Service baseline storage/readiness clauses for `hasna.contract.json`,
  `/ready`, and readiness evidence bundles.
