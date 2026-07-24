# Infra Service Entrypoint Matrix

Date: 2026-07-06

Source tasks:

- `0c8caca6-c564-4ad3-a878-23a8405ca2bc` - Add infra service binaries and deployment contracts.
- `reports/task-proposals/adversarial-12/reviewer-02-open-infra.md` proposal 4.
- `reports/task-proposals/adversarial-12/reviewer-09-service-baseline.md` SVC-01 through SVC-03.
- `reports/task-proposals/adversarial-12/reviewer-12-final-dedupe.md` task 17.

This matrix is intentionally conservative. A `*-serve` package bin is only
`supported` when the repo already exposes a service boundary that can declare
health/version routes, auth behavior, deployment modes, and readiness gates in
`hasna.contract.json`. Repos with raw secret values, undefined hosted auth, or
missing state ownership must use `deferred` instead of publishing a broad server
bin.

| Repo | Package | Current bins | Service decision | Required next contract evidence |
| --- | --- | --- | --- | --- |
| `open-backup` | `@hasna/backup@0.1.2` | `backup`, `backup-mcp` | `deferred` | Define hosted state owner, backup target credential refs, `/health`, `/ready`, redacted inventory output, and restore-smoke evidence before `backup-serve`. |
| `open-bridge` | `@hasna/bridge@0.2.1` | `bridge`, `bridge-mcp` | `deferred` | Define bridge auth scopes, connector secret refs, event replay boundaries, and no-secret output gates before `bridge-serve`. |
| `open-domains` | `@hasna/domains@0.0.27` | `domains`, `domains-mcp`, `domains-serve` | `supported` | Add/refresh `hasna.contract.json` service surface with `local` and `self_hosted` support, `/health`, `/ready`, `/version`, `/v1`, provider-credential readiness gates, dry-run DNS mutation gates, and redaction tests. Keep concrete secret refs in private deployment config. |
| `open-hooks` | `@hasna/hooks@0.2.20` | `hooks` | `deferred` | Decide whether hooks is CLI-only, MCP-capable, or service-capable; service mode needs webhook signature/replay gates and operator-visible DLQ before `hooks-serve`. |
| `open-machines` | `@hasna/machines@0.0.63` | `machines`, `machines-mcp`, `machines-agent`, `machines-serve` | `supported` | Add/refresh service surface with lease/claim auth scopes, private metadata redaction, `/v1` ownership boundaries, and fleet dry-run fixture gates. |
| `open-releases` | `@hasna/releases@0.1.0` | `releases`, `releases-mcp` | `deferred` | Promote release evidence schema and append-only ledger first; then add `releases-serve` with package/version/gate/evidence APIs and unauthorized mutation denial. |
| `open-secrets` | `@hasna/secrets@0.1.33` | `secrets`, `secrets-mcp`, `secrets-serve` | `deferred` for hosted raw-value access | Hosted service surfaces must declare secret-reference and lease semantics, local-only reveal exclusions, audit gates, and tests proving HTTP/MCP never returns raw secret values. |
| `open-servers` | `@hasna/servers@0.1.21` | `servers`, `servers-mcp` | `deferred` | Define lifecycle locks, operation ids, job-scoped auth, command/env redaction, and registered-server boundaries before `servers-serve`. |
| `open-uptime` | `@hasna/uptime@0.1.69` | `uptime`, `uptime-mcp` | `deferred` pending standard bin | Existing `serve` command should either publish `uptime-serve` or declare `serve: unsupported`; contract needs probe storage readiness and redacted status gates. |
| `open-gateway` | `@hasna/gateway@0.1.3` | `gateway`, `gateway-mcp` | `deferred` until gateway runtime task completes | Add `gateway-serve` only with auth, secret references, budget/ledger readiness gates, redacted diagnostics, CORS policy, and mock chat smoke. |
| `open-monitor` | `@hasna/monitor@0.1.24` | `monitor`, `monitor-mcp`, `monitor-server`, `monitor-web` | `supported with alias decision` | Either add `monitor-serve` as an alias or declare `monitor-server` as the canonical exception; service surface must include health/readiness/version and redacted machine metadata. |

## Contract fields to use

Use `hasna.service_contract.v1` with:

- `hosting`: `user-hosted` and, only when a managed control plane exists,
  `hasna-saas`.
- `deploymentModes`: one or more of `local`, `self_hosted`, `cloud`. The old
  `self-hosted` spelling is parse-only migration input. Do not use `remote` as a
  deployment mode.
- `serviceSurfaces[]`: typed API, SDK, MCP, and CLI records.
- `serviceSurfaces[].kind`: `api`, `sdk`, `mcp`, or `cli`.
- `serviceSurfaces[].status`: `supported`, `deferred`, or `unsupported`.
- `serviceSurfaces[].deferReason`: required for `deferred` and `unsupported`.
- `serviceSurfaces[kind=sdk].exportSubpath`: a real `package.json` export key.
- `storage.engines`: both `sqlite` and `postgres` for store-owning OSS cores.
- `storage.pgTestGate`: the disposable live-Postgres test env var and command;
  conformance records this command but never executes it.
- `serviceSurfaces[].readinessGates[]`: auth, storage, secret-ref, migration,
  health, readiness, redaction, smoke, and operator gates with command/evidence
  status when available.

## First implementation tasks

1. Apply this contract to `open-domains`, `open-machines`, and `open-monitor`
   first because they already expose service/server bins.
2. Complete the separate `open-gateway` runtime task before declaring
   `gateway-serve` supported.
3. Keep `open-secrets` hosted service deferred until raw-value reveal is
   strictly local-only and network surfaces return refs/leases only.
4. Create app-specific tasks for `open-releases`, `open-servers`, and
   `open-uptime` once the service boundary and readiness owner are agreed.
