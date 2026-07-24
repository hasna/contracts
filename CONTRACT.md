# Hasna Service Contract v1

Normative specification for how every Hasna open-source (`open-*`) package
describes itself, stores its data, exposes health, names its bins and secrets,
and proves it does not depend on a shared cloud runtime.

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are used per RFC 2119.

The machine-readable half of this contract is `hasna.contract.json` at each repo
root, validated by `hasna.service_contract.v1` (Zod: `ServiceContractManifestSchema`,
JSON Schema: `src/hasna.contract.schema.json`). Repos verify themselves with the
conformance kit (`runRepoConformance` / `contracts repo-conformance`).

---

## 1. Docs tiers

Documentation and deployment guidance is organized into three tiers. These are
**documentation tiers**, not runtime modes.

| Tier | Meaning |
| --- | --- |
| `local` | Single developer machine. SQLite is authoritative. No network store. |
| `self_hosted` | Operator runs the app against their own Postgres (and their own object store if any). Delivered via the repo's root `docker-compose.yml`. |
| `cloud` | Hasna-operated managed offering (SaaS). |

`self_hosted` is a distinct runtime placement. Its server process uses the
**`cloud` storage mode** pointed at an operator-owned private database URL.

---

## 2. Runtime storage mode (Amendment A1 — PURE REMOTE)

The runtime storage enum is **`local | cloud` ONLY**.

- **`local`** — SQLite at `~/.hasna/<name>/<name>.db` is authoritative.
- **`cloud`** — reads **AND** writes go **directly** to the app-owned cloud
  Postgres.

**Amendment A1 (PURE REMOTE), spelled out — overrides everything:**

1. `cloud` mode means both reads and writes hit the cloud Postgres directly.
2. There is **NO** sync engine.
3. There is **NO** cache-as-mode (no "hybrid", no "local cache" runtime).
4. There is **NO** merge logic and **NO** conflict resolution.
5. After a one-time migration, the local SQLite file becomes a dated backup
   file (`<name>.db.pre-cloud.<YYYYMMDD>`), not a live read path.
6. The **only** sanctioned exception is the OpenTodos dual-write **SHADOW**:
   during a pre-cutover validation window, writes MAY be mirrored async
   local→cloud for comparison; **reads stay local** and the app **never reads
   from cloud** in shadow. Shadow is a migration step, not a runtime mode.

The words `remote`, `hybrid`, and `self_hosted` are accepted as deprecated
**storage-mode** aliases that normalize to `cloud`. This does not erase the
separate runtime-placement meaning of `self_hosted`: manifests write
`deploymentModes: ["self_hosted"]` for an operator-run server. The old
hyphenated deployment spelling `self-hosted` still parses for migration and is
canonicalized to `self_hosted`.

The reference normalizer lives in `src/mode.ts`, extracted from open-mailery's
`normalizeMaileryMode`.

---

## 3. Environment specification

Each app with a store resolves its mode and database URL from the environment.

| Key | Purpose |
| --- | --- |
| `HASNA_<NAME>_STORAGE_MODE` | Canonical mode selector. Value `local` or `cloud`. |
| `HASNA_<NAME>_DATABASE_URL` | Cloud Postgres URL. **Required when mode is `cloud`.** |
| `<NAME>_STORAGE_MODE` | Optional short alias for the mode selector. |
| `<NAME>_DATABASE_URL` | Optional short alias for the database URL. |

`<NAME>` is the upper-snake form of the app name (e.g. `todos` → `TODOS`,
`open-mailery` app name `mailery` → `MAILERY`).

Resolution precedence (see `resolveStorageMode`):

1. `HASNA_<NAME>_STORAGE_MODE`
2. `<NAME>_STORAGE_MODE` (alias; emits a "use canonical key" warning)
3. default → `local`

An app **MUST NOT** read secret *values* to decide the mode; it only detects
`DATABASE_URL` presence. Selecting `cloud` without a database URL is a
misconfiguration and MUST warn.

---

## 4. Health endpoints (services)

Any repo that ships a `<name>-serve` bin **MUST** expose:

| Endpoint | Response shape | Schema |
| --- | --- | --- |
| `GET /health` | `{ "status": "ok"\|"degraded"\|"unavailable", "version": string, "mode": "local"\|"cloud" }` | `HealthResponseSchema` |
| `GET /ready` | `{ "ready": boolean, "reason"?: string }` | `ReadyResponseSchema` |
| `GET /version` | `{ "version": string }` | `VersionResponseSchema` |

`/health` reports liveness and the active storage mode. `/ready` reports whether
the app can serve traffic (e.g. database reachable). `/version` reports the
package version.

---

## 5. Bins

The bin allowlist for an app named `<name>` is:

```
<name>            # primary CLI
<name>-cli        # explicit CLI alias
<name>-mcp        # MCP server (HTTP transport)
<name>-serve      # HTTP/REST service
<name>-worker     # background worker
<name>-runner     # workflow/job runner
<name>-daemon     # long-lived daemon
<name>-migrate    # migration tool
<name>-doctor     # diagnostics
```

Repos **MUST NOT** declare bins outside this allowlist without an explicit
per-repo waiver recorded in `hasna.contract.json` review. `library` repos
**MUST NOT** ship a `-serve` or `-mcp` bin. Declared `bins` **MUST** match the
`bin` map in `package.json`.

---

## 6. Storage capabilities and private secret bindings

- **Local SQLite path:** `~/.hasna/<name>/<name>.db`.
- `storage.sqlitePath` **MUST** end in `.db`.
- Store-owning OSS cores declare `storage.engines: ["sqlite", "postgres"]`.
- A PostgreSQL capability declaration **MUST** include `storage.envPrefix`, so
  the serve/migrate boundary can derive `HASNA_<NAME>_DATABASE_URL`.
- `storage.pgTestGate` records the disposable live-Postgres test env var and
  command. Conformance records the command as data and never executes it.

Public OSS manifests **MUST NOT** contain secret-reference paths, internal
company hostnames, cloud ARNs, or account IDs. Concrete database secret
bindings belong in private deploy/infra configuration. The resolved URL is
supplied to the server as `HASNA_<NAME>_DATABASE_URL` at runtime and is never
baked into an image or committed. The legacy `databaseUrlSecretRef` field
remains parseable for private-tier compatibility, but public conformance rejects
it.

---

## 7. Self-host artifact

Every `service`, `saas`, and `cli-with-store` repo that ships a `<name>-serve`
bin **MUST** ship at least one root self-host artifact: `docker-compose.yml`,
`docker-compose.yaml`, `compose.yml`, `compose.yaml`, or `Dockerfile`. A Compose
file is the preferred complete reference because it can bring up an app-owned
Postgres and the app in `cloud` mode pointed at it. See this repo's
`docker-compose.yml` for the reference template.

---

## 8. Repo classes

Every repo declares exactly one `class`. Each class has a minimum ship list.

### `library`
Ships types/validators/helpers. No store, no service.
- **MUST NOT** declare `storage`.
- **MUST NOT** ship a `-serve` or `-mcp` bin.
- MAY ship `<name>` / `<name>-cli` bins for local checks.

### `cli-with-store`
A CLI that owns local (and optionally cloud) data.
- **MUST** declare `storage`.
- **MUST** declare both `sqlite` and `postgres` in `storage.engines`.
- If `storage.mode` is `local`, **MUST** set `storage.sqlitePath`
  (`~/.hasna/<name>/<name>.db`).
- **MUST** declare `storage.pgTestGate`.
- **MUST** ship the `<name>` bin.
- SHOULD ship a `<name>-mcp` bin for agent access.
- A CLI-only repo is required to declare only its supported CLI surface;
  conformance does **not** force API, SDK, or MCP surfaces onto it.
- If it ships `<name>-serve`, it becomes service-capable for conformance and
  **MUST** declare supported API, SDK, MCP, and CLI surfaces, expose
  `GET /health`, `GET /ready`, and `GET /version`, and ship a root self-host
  artifact.

### `service`
A long-running HTTP/MCP service.
- **MUST** declare `storage`.
- **MUST** declare both `sqlite` and `postgres` in `storage.engines`.
- **MUST** declare `storage.pgTestGate`.
- **MUST** ship a `<name>-serve` bin and expose `GET /health`, `GET /ready`,
  and `GET /version`.
- **MUST** ship a root self-host artifact.
- SHOULD ship a `<name>-mcp` bin.

### `saas`
A Hasna-operated managed service.
- **MUST** declare the `hasna-saas` hosting story.
- **MUST** declare `storage` with `storage.mode` = `cloud`.
- **MUST** declare `storage.envPrefix`; concrete database secret bindings stay
  in private deployment configuration, not the public manifest.
- **MUST** ship a `<name>-serve` bin and expose `GET /health`, `GET /ready`,
  and `GET /version`.
- **MUST** ship a root self-host artifact for parity/self-host.

All classes **MUST** pass the no-cloud guard: no dependency on a shared cloud
runtime (`FORBIDDEN_SHARED_CLOUD_RUNTIMES`). App-owned cloud is declared per app
via `AppCloudManifest`; it is never a shared runtime import.

---

## 9. `hasna.contract.json`

Each repo root carries a `hasna.contract.json`. Product hosting, runtime
placement, storage routing, storage capabilities, and product surfaces are
separate axes:

```json
{
  "$schema": "./node_modules/@hasna/contracts/dist/hasna.contract.schema.json",
  "schema": "hasna.service_contract.v1",
  "name": "todos",
  "class": "cli-with-store",
  "contractVersion": "v1",
  "kitVersion": "0.7.0",
  "bins": ["todos", "todos-mcp", "todos-serve"],
  "hosting": ["user-hosted", "hasna-saas"],
  "deploymentModes": ["local", "self_hosted", "cloud"],
  "storage": {
    "mode": "local",
    "engines": ["sqlite", "postgres"],
    "envPrefix": "HASNA_TODOS_",
    "aliasEnvPrefix": "TODOS_",
    "sqlitePath": "~/.hasna/todos/todos.db",
    "pgTestGate": {
      "envVar": "TODOS_TEST_DATABASE_URL",
      "command": "bun test tests/postgres-storage.test.ts"
    }
  },
  "serviceSurfaces": [
    {
      "name": "http-api",
      "kind": "api",
      "status": "supported",
      "bin": "todos-serve",
      "authMode": "api-key",
      "deploymentModes": ["local", "self_hosted", "cloud"],
      "health": { "method": "GET", "path": "/health", "public": true },
      "readiness": { "method": "GET", "path": "/ready", "public": false },
      "version": { "method": "GET", "path": "/version", "public": true },
      "apiBasePath": "/v1",
      "openApiPath": "/openapi.json"
    },
    {
      "name": "typescript-sdk",
      "kind": "sdk",
      "status": "supported",
      "authMode": "api-key",
      "deploymentModes": ["local", "self_hosted", "cloud"],
      "exportSubpath": "./sdk",
      "generatedFrom": "/openapi.json",
      "clientClassName": "TodosClient"
    },
    {
      "name": "mcp",
      "kind": "mcp",
      "status": "supported",
      "mcpBin": "todos-mcp",
      "authMode": "api-key",
      "deploymentModes": ["local", "self_hosted", "cloud"]
    },
    {
      "name": "cli",
      "kind": "cli",
      "status": "supported",
      "bin": "todos",
      "authMode": "local-only",
      "deploymentModes": ["local", "self_hosted"]
    }
  ]
}
```

- `contractVersion` — the Service Contract version the repo targets (`v1`).
- `kitVersion` — the `@hasna/contracts` version the repo tracks.
- `hosting` — product stories: `user-hosted` and, only when available,
  `hasna-saas`.
- `deploymentModes` — runtime placements: `local`, `self_hosted`, `cloud`.
  The old `self-hosted` spelling parses as a deprecated alias.
- `storage.mode` — active storage router (`local | cloud`), distinct from
  placement.
- `storage.engines` — supported persistence engines.
- `serviceSurfaces` — supported product-surface declarations. Service-capable
  repos declare API, SDK, MCP, and CLI; a CLI-only `cli-with-store` declares
  only its CLI. A supported SDK names a real package `exports` key via
  `exportSubpath`, and the export target must exist in the built package or
  have a corresponding source entry before build. Generated clients reference
  the API's `openApiPath` via `generatedFrom`.

Libraries may waive only API and MCP because they remain responsible for their
SDK and CLI surfaces. Exceptional non-Node monorepos may waive any inapplicable
surface only when they declare the explicit `non-node-monorepo` waiver profile:

```json
{
  "metadata": {
    "conformance": {
      "waiverProfile": "non-node-monorepo",
      "waivedSurfaces": [
        {
          "kind": "api",
          "reason": "Execution-free schema library; no HTTP runtime."
        }
      ]
    }
  }
}
```

A waiver is typed, unique per surface kind, and must carry a non-empty reason.
`service`, `saas`, and service-capable `cli-with-store` repos without the
non-Node profile cannot use waivers to bypass required supported surfaces.

---

## 10. Conformance

A repo proves compliance by running the conformance kit against its own root:

```bash
contracts repo-conformance .
contracts repo-conformance --json .
```

Or programmatically / in a `bun test`:

```ts
import { runRepoConformance } from "@hasna/contracts";
const report = runRepoConformance(process.cwd());
if (!report.ok) throw new Error(JSON.stringify(report.checks, null, 2));
```

Checks:

1. `manifest_valid` — `hasna.contract.json` present and valid (class rules enforced).
2. `bins_allowlisted` — declared bins are in the allowlist.
3. `bins_match_package` — declared bins match `package.json` `bin`.
4. `surface_matrix` — the class-appropriate supported surface kinds are
   declared or explicitly waived. CLI-only `cli-with-store` repos require only
   CLI; service-capable repos require API, SDK, MCP, and CLI.
5. `surface_bindings` — surface bins and SDK export subpaths exist in
   `package.json`; generated SDKs reference a declared OpenAPI path.
6. `service_api_topology` — service-capable repos declare supported
   `GET /health`, `GET /ready`, and `GET /version` endpoints.
7. `self_host_artifact` — service-capable repos ship a root Compose file or
   `Dockerfile`.
8. `storage_capabilities` — store-owning cores declare SQLite + PostgreSQL,
   `storage.envPrefix`, and a live-PG test gate; SaaS declares its public
   PostgreSQL env prefix.
9. `public_manifest_safety` — public manifests contain no secret or credential
   refs, credential-shaped values, internal hosts, ARNs, or account IDs.
10. `hosting_story` — public OSS cores include the user-hosted product story;
   `saas` repos include the `hasna-saas` story.
11. `mode_enum_compliance` — any `HASNA_<NAME>_STORAGE_MODE` env normalizes to `local|cloud`.
12. `health_shape` — when a serve bin exists, a sampled `/health` payload matches `{ status, version, mode }`.
13. `no_cloud_guard` — no forbidden shared cloud runtime edges (reuses `scanNoCloudTarget`).

The kit is dev-dependency friendly: `@hasna/contracts` can be a `devDependency`
and the checks run under `bun test` with no runtime footprint in the app.

---

## 11. Secure local-store lifecycle

The shared secure local-store policy is `hasna.secure_local_store_policy.v1`
(`SecureLocalStorePolicySchema`) and the helper module is
`@hasna/contracts/secure-local-store`.

This policy describes local operator state under `.hasna` and `.codewith`.
The default inventory is explicit by package: Codewith, Todos, Conversations,
Mementos, Knowledge, Projects, Browser, Terminal, Logs, and Loops. It is a
declarative contract only: `@hasna/contracts` does not inspect or mutate any of
those stores.

Local stores **MUST** use owner-only defaults:

- Store directories: `0700`.
- Store files: `0600`.
- SQLite main DB files, WAL sidecars, and SHM sidecars: `0600`.
- Backup, export, report, session, snapshot, tmp, and log artifacts: `0600`
  unless a package records a narrower non-secret exception.

An owning package that implements lifecycle cleanup **MUST** default to dry-run.
Destructive retention requires:

1. Explicit apply intent.
2. A package-owned retention adapter.
3. Artifact allowlist matches; no broad delete outside the allowlist.
4. Active-record exclusion proof for current tasks, sessions, messages, runs,
   workspace rows, attachments, evidence, or other package-owned references.
5. Redaction-before-persistence and redacted evidence from the owning package.

SQLite maintenance **MUST NOT** run against active stores. WAL checkpoint,
incremental vacuum, optimize, or vacuum operations are allowed only when the
owning package explicitly proves exclusive/offline access for that store.
Contracts retains the policy/profile/proof declarations but does not open
SQLite, run maintenance, scan paths, change permissions, or delete files.

The CLI surface:

```bash
contracts secure-local-store --json
contracts secure-local-store --json --store todos
```

The CLI only prints the validated declarative policy, optionally filtered by
store id. It never accepts a filesystem root and never plans or applies
permissions, retention, deletion, or SQLite operations. Execution and redacted
proof remain the responsibility of each owning package.

---

## 12. Migration from 0.4.x/0.5.x manifests

Existing `deploymentModes: ["self-hosted"]` values normalize to `self_hosted`;
missing `hosting`, `deploymentModes`, and `serviceSurfaces` still receive
compatible defaults, so legacy manifests such as OpenLoops remain
schema-readable. The current schema intentionally rejects a declared
non-`.db` `storage.sqlitePath`, a SaaS store without `storage.envPrefix`, and a
declared supported API that omits the health/readiness/version endpoints or
uses a method other than `GET`.

Conformance is stricter than schema parsing. A legacy service manifest can
remain schema-valid while failing new checks until it:

1. declares the class-appropriate surfaces: CLI for a CLI-only
   `cli-with-store`, or API, SDK, MCP, and CLI for service-capable repos;
2. declares `GET /health`, `GET /ready`, and `GET /version` for each supported
   service API;
3. points SDK declarations at real package exports;
4. declares SQLite + PostgreSQL capabilities, `storage.envPrefix`, and a
   `pgTestGate` where required;
5. adds a root self-host artifact when it ships a service;
6. removes private infrastructure references from the public manifest; and
7. writes canonical `self_hosted` runtime placement spelling.

Conformance treats `pgTestGate.command` and every other manifest command as
data only; it never executes them.

These additive v1 capability declarations do not consume the separately
planned `hasna.service_contract.v2`. V2 remains reserved for breaking API-base,
operation-registry, authorization, worker, and deployment-control-plane
semantics.
