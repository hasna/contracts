# Provider Live-Mode Safety Standard

Date: 2026-07-06

This standard applies to provider adapters in built or partially built `open-*`
and `iapp-*` apps. It excludes platform apps, empty apps, README-only apps,
scaffold-only apps, stale clone-only roots, and license-only repos.

Provider work must default to no side effects. Live mutation is allowed only
after sandbox proof, explicit operator approval, credential-reference checks,
idempotency, rollback or revocation evidence, and reconciliation evidence are
present.

## Canonical Provider Modes

- `mock`: deterministic fake implementation. No provider credentials and no
  provider calls.
- `fixture`: recorded or local test data. No provider calls.
- `sandbox`: provider sandbox or test account. No production user, domain, DNS,
  money, call, message, or filing side effects.
- `read_only_live`: live provider reads only. No mutation endpoints or outbound
  delivery paths.
- `live_mutating`: live provider side effects. Requires all gates below.

Apps must expose provider mode in CLI JSON, MCP output, API response metadata,
health/readiness, audit/provenance, and operator evidence without printing
secret values.

## Required Capability Card

Every provider adapter must publish a `ProviderCapabilityCard` with:

- provider id, app id, adapter id, and owner package
- supported modes and default mode
- credential refs or lease refs required per mode
- operation cards with side-effect class and supported modes
- rate-limit and cost posture
- audit event names
- redaction rules
- evidence refs for validation, sandbox proof, and no-side-effect smokes

Raw provider secrets are not accepted in CLI args, MCP args, reports, logs, task
comments, committed config, or package examples. Missing or revoked credentials
must fail closed with a typed diagnostic.

## Live Mutation Gate

An operation may run in `live_mutating` only when all checks pass:

- requested mode is exactly `live_mutating`
- provider capability card allows the operation in `live_mutating`
- required credential refs or leases resolve and revocation checks pass
- approval record is approved, unexpired, and linked to the operation digest
- idempotency key is present
- sandbox evidence predates live execution
- rollback or revocation path is recorded
- reconciliation target is recorded

Environment flags alone must never enable live mutation. Fallback from live to
fixture/mock is forbidden for production commands because it can hide missing
authority or stale provider proof.

## Validation Gates

At minimum, adopters must run:

- native repo verification: `bun run verify` where available, otherwise
  `bun run typecheck`, `bun test`, and `bun run build`
- provider conformance suite with no real side effects
- disabled-live smoke proving env flags alone cannot bypass gates
- secret-output scan over CLI, MCP, HTTP logs, reports, errors, and task evidence
- webhook/signature/replay fixtures where inbound providers are present

Live proof comes after sandbox proof. Live mutation additionally requires
operator approval and rollback or disable evidence.

## First Adoption Targets

- `open-mailery`: canonical `open-mailery`/`open-emails` boundary, local versus
  self-hosted versus cloud auth model, Postgres/S3/SES readiness, signed
  webhooks, and no-send/domain-change smokes.
- `open-telephony`: REST auth, Twilio signature and replay validation, toll
  fraud controls, durable queues, retention, and opt-in sandbox/live provider
  smokes.
- `open-feedback`: public submit separated from private read/export/triage,
  scoped auth, rate/spam limits, durable store, dedupe, and signed forwarding
  webhooks.

The machine-readable fixture is
`examples/provider-live-mode-standard.valid.json`.
