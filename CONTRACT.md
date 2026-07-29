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

## 1. Product stories

Every Hasna OSS product has exactly **two** customer-facing stories, declared
in the manifest's `hosting` array. There is no third.

| Story | Meaning |
| --- | --- |
| `user-hosted` | The user runs the whole thing, in any environment of theirs. SQLite by default, their own PostgreSQL by choice. |
| `hasna-saas` | Hasna operates the product as a multi-tenant SaaS. |

The deployment-placement axis that used to sit next to this (three runtime
placements plus aliases) was **removed entirely** (owner directive 2026-07-29).
Where something ran never changed how it stored data; the only switch a repo
carries is its server's **data backend**.

---

## 2. Data backend (storage mode)

The storage enum is **`sqlite | postgres` ONLY**, and it describes the
**SERVER's internal storage**:

- **`sqlite`** — SQLite at `~/.hasna/<name>/<name>.db` is authoritative.
- **`postgres`** — reads **AND** writes go to a PostgreSQL server
  (`DATABASE_URL`). Who operates that server — the user or Hasna — does not
  change the backend, the code path, or this contract.

Invariants, spelled out — these override everything:

1. `postgres` means both reads and writes hit PostgreSQL directly.
2. There is **NO** sync engine.
3. There is **NO** cache-as-backend (no blended local-cache runtime).
4. There is **NO** merge logic and **NO** conflict resolution.
5. After a one-time migration, the local SQLite file becomes a dated backup
   file (`<name>.db.pre-postgres.<YYYYMMDD>`), not a live read path.
6. The **only** sanctioned exception is the OpenTodos dual-write **SHADOW**:
   during a pre-cutover validation window, writes MAY be mirrored async
   sqlite→postgres for comparison; **reads stay on sqlite** and the app
   **never reads from postgres** in shadow. Shadow is a migration step, not a
   backend.

The **OSS client is `sqlite`-or-HTTP** and **never opens PostgreSQL
directly**: a client whose data lives in the server's PostgreSQL reaches it
over the HTTP `/v1` API (see `resolveClientTransport`). There is no
client-side Postgres store.

The removed placement vocabulary (`local`, `cloud`, `remote`, the
operator-hosted placement word in both its underscore and hyphen spellings,
and the blended-cache word) is **rejected with a migration hint**, never
silently mapped. The long spelling `postgresql` normalizes to `postgres`. The
reference normalizer lives in `src/mode.ts`.

---

## 3. Environment specification

Each app with a store resolves its backend and database URL from the
environment.

| Key | Purpose |
| --- | --- |
| `HASNA_<NAME>_STORAGE_MODE` | Canonical backend selector. Value `sqlite` or `postgres` (`postgresql` accepted as the long spelling). |
| `HASNA_<NAME>_DATABASE_URL` | PostgreSQL URL. **Required when the backend is `postgres`.** |
| `<NAME>_STORAGE_MODE` | Optional short alias for the backend selector. |
| `<NAME>_DATABASE_URL` | Optional short alias for the database URL. |

`<NAME>` is the upper-snake form of the app name (e.g. `todos` → `TODOS`,
`open-mailery` app name `mailery` → `MAILERY`).

Resolution precedence (see `resolveStorageMode`):

1. `HASNA_<NAME>_STORAGE_MODE`
2. `<NAME>_STORAGE_MODE` (alias; emits a "use canonical key" warning)
3. default → `postgres` when a `DATABASE_URL` is present, else `sqlite`

An app **MUST NOT** read secret *values* to decide the backend; it only
detects `DATABASE_URL` presence. Selecting `postgres` without a database URL
is a misconfiguration and MUST warn.

### 3a. Credential resolution — env holds a pointer, disk holds the secret

Environment variables are a snapshot taken at process start; credentials are
mutable state. Storing a rotating secret in a frozen snapshot is a defect, and
it has a measured failure mode: a shell started before a key rotation keeps
sending the old key for its entire life, so every command from that shell fails
`401` while a fresh shell on the same machine in the same second succeeds.

Apps **MUST NOT** read `HASNA_<NAME>_API_KEY` from `process.env` themselves.
The credential is resolved by the transport, at call time, through
`resolveCredential()` (re-exported from `@hasna/contracts/client`). Precedence:

| # | Tier | Source | Notes |
| --- | --- | --- | --- |
| 1 | argument | `--api-key` / `--profile` passed by the caller | Deliberate. |
| 2 | override | `HASNA_<NAME>_API_KEY_OVERRIDE`, or the `HASNA_PROFILE` pointer | Deliberate. Nothing sets these automatically. |
| 3 | **disk** | `$HOME/.hasna/cloud/<name>.env`, then `$HOME/.config/hasna/<name>-cloud.env` | **The default path.** Re-read on every call. |
| 4 | legacy env | `HASNA_<NAME>_API_KEY` / `<NAME>_API_KEY` | Deprecated fallback, used only when the disk yields nothing. Warns once per app. |

Rules:

- **A deliberate tier never falls through.** If tier 1 or 2 selects a
  credential, the chain stops there. An override that is revoked MUST surface
  as a `401`; silently continuing to the next tier would authenticate as a
  different principal than the operator named. There is **no retry-on-401**:
  with a single static key, a retry makes identity nondeterministic per call
  and is precisely what rescues a revoked override as the wrong tenant.
- **Tier 3 is re-read per request**, not cached and not resolved once when the
  client is built — a cache is the same snapshot defect at a smaller timescale.
  This is what makes a rotation heal in any shell, however old.
- **A credential alone never routes anything to the network.** An explicit
  `HASNA_<NAME>_STORAGE_MODE` always wins, and it is still read only from the
  environment. Where no mode is set, the legacy flip signal (`API_URL` +
  `API_KEY` both present) still applies, but its credential half is satisfied by
  **any** tier of the chain, not only by the legacy env var. The **API URL is
  still required and still env-only**, so a credential file on disk cannot flip
  a client that has no endpoint configured.

  This matters because the steady state this section tells operators to migrate
  to — endpoint in the environment, credential on disk — would otherwise resolve
  to `sqlite` with `misconfigured: false` and no warning, silently serving the
  local dataset while a valid credential sat on disk. That is the false green
  this section forbids, so the inference has to see the whole chain.
- **`HOME` comes from the same env object** the caller passes. An env with no
  `HOME` performs no disk read, which is what keeps the behaviour hermetic and
  test suites independent of the machine running them.
- **Never fall back to local data on an auth failure.** Offline reads are a
  legitimate feature, but they MUST be a deliberate mode chosen *before* the
  request. A `401`-to-local fallback prints healthy output while authentication
  is broken — a false green, strictly worse than the loud failure.
- **A credential source that cannot produce a usable key fails loudly.** A key
  carrying bytes that are illegal in an HTTP header is rejected by name, never
  forwarded — otherwise `fetch` throws a `TypeError` that embeds the whole
  header value, i.e. the plaintext key, into logs and stack traces. Credential
  files are read only when they are regular files under a size cap, so a FIFO
  or a character device planted in the credential directory cannot wedge a
  per-request read.
- **Every credential is built by one of exactly two constructors** —
  `resolveCredential()` for the chain, `explicitCredential()` for a key a caller
  passes directly as a string to `createHasnaHttpTransport({ apiKey })`. Both
  validate and seal. A construction site that skips them is a bypass of this
  whole section, and the string branch WAS one: it built a plain object literal,
  so the single most-used public entry point ran neither the header-byte check
  nor the seal.
- Errors name **which source** supplied the rejected key, and say what to do
  about it. Where two sources disagree, the report names the **paths** only: a
  digest of a secret is still a derived encoding of it, and a truncated one is a
  confirmation oracle.
- **A key value is never logged, embedded, serialized, or printed**, and each of
  those is enforced separately because one mechanism does not cover them all:

  | Channel | Enforcement |
  | --- | --- |
  | `Object.keys`, `{ ...resolution }`, `JSON.stringify` | the field is **non-enumerable** |
  | `console.log`, `Bun.inspect` | a **non-enumerable `Symbol.for("nodejs.util.inspect.custom")` hook** that renders `apiKey: "[redacted]"` |

  Non-enumerability alone is NOT sufficient: under Bun — the engine this package
  declares — an inspector prints own non-enumerable properties, so
  `console.log(resolution)` spilled the key in plaintext while this section
  claimed it could not. A redacting `toJSON` is not an alternative; a
  non-enumerable one is never invoked by `JSON.stringify` in this runtime, and an
  enumerable one would put a function into `Object.keys` and into every spread.

---

## 4. Health endpoints (services)

Any repo that ships a `<name>-serve` bin **MUST** expose:

| Endpoint | Response shape | Schema |
| --- | --- | --- |
| `GET /health` | `{ "status": "ok"\|"degraded"\|"unavailable", "version": string, "mode": "sqlite"\|"postgres" }` | `HealthResponseSchema` |
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
- A store-owning core **MUST** declare both `storage.envPrefix` and
  `storage.pgTestGate` **unless** PostgreSQL is explicitly waived. Not declaring
  the engine does not remove the obligation; only a valid waiver does.

### Explicit storage-engine waivers

PostgreSQL remains the target for every store-owning core, but a waiver-eligible
`cli-with-store` repo (see the conditions below) MAY ship SQLite-only for an
honest intermediate state by declaring an explicit, auditable waiver instead of
fabricating PostgreSQL support:

```json
{
  "storage": {
    "mode": "sqlite",
    "engines": ["sqlite"],
    "envPrefix": "HASNA_FACTORY_",
    "sqlitePath": "~/.hasna/factory/factory.db"
  },
  "metadata": {
    "conformance": {
      "waivedStorageEngines": [
        {
          "engine": "postgres",
          "reason": "SQLite-only local CLI; PostgreSQL adoption is tracked through the vendored storage kit.",
          "reviewedBy": "platform-storage",
          "expiresAt": "2027-01-01T00:00:00.000Z"
        }
      ]
    }
  }
}
```

- A storage waiver is typed, unique per engine, and **MUST** carry a non-empty
  `reason`. `reason` and `reviewedBy` are echoed into the conformance report, so
  they are length-bounded (500 / 200 characters) and **MUST NOT** contain
  control characters. A waiver whose prose cannot be printed — because it
  carries a secret reference, internal host, ARN, or account id — **fails** the
  storage gate: an exception nobody can read is not auditable.
- `reviewedBy` and `expiresAt` are optional. `expiresAt` is a UTC RFC 3339
  timestamp (`Z`, e.g. `2027-01-01T00:00:00.000Z`); conformance **fails** the
  storage gate once it has passed, so a time-boxed exception cannot silently
  become permanent.
- Only `postgres` is waivable. SQLite is the local source of truth and is never
  waivable.
- A waiver is an admission that a repo has no PostgreSQL support, so it is
  refused for every manifest that already claims PostgreSQL is in play. Only a
  `cli-with-store` repo that
  1. does **not** ship `<name>-serve` (a serve bin makes it service-capable),
  2. declares `storage.mode` `sqlite` (`postgres` reads and writes PostgreSQL
     directly), and
  3. does **not** declare the `hasna-saas` product story
  may waive an engine. `service` and `saas` repos never may.
- A waiver for an engine the manifest already declares is redundant: the engine
  keeps its normal proof obligations, including `storage.pgTestGate`.
- Waivers are additive. A manifest without `waivedStorageEngines` gets the same
  verdict and the same report text as before, with one exception: the
  `manifest_valid` failure message for a sqlite-only `cli-with-store` now names
  the waiver mechanism.
- Most existing `cli-with-store` repos are **not** eligible today, because they
  ship `<name>-serve`. That is deliberate for a first version: widening the
  waiver later is backwards-compatible, narrowing it after repos have banked a
  green build is not.

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
- **MUST** declare both `sqlite` and `postgres` in `storage.engines`, unless it
  is waiver-eligible (CLI-only, `local` storage mode, no `cloud` placement, no
  `hasna-saas` story) and `postgres` carries an explicit
  `metadata.conformance.waivedStorageEngines` waiver (see §6). `sqlite` is
  never waivable.
- If `storage.mode` is `local`, **MUST** set `storage.sqlitePath`
  (`~/.hasna/<name>/<name>.db`).
- **MUST** declare `storage.envPrefix` and `storage.pgTestGate` unless
  PostgreSQL is explicitly waived; a waived engine has no DATABASE_URL boundary
  to derive and no live-PG gate to declare.
- **MUST** ship the `<name>` bin.
- SHOULD ship a `<name>-mcp` bin for agent access.
- A CLI-only repo is required to declare only its supported CLI surface;
  conformance does **not** force API, SDK, or MCP surfaces onto it.
- If it ships `<name>-serve`, it becomes service-capable for conformance and
  **MUST** declare supported API, SDK, MCP, and CLI surfaces, expose
  `GET /health`, `GET /ready`, and `GET /version`, ship a root self-host
  artifact, and declare the full storage-engine matrix (no storage waiver).

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
  "storage": {
    "mode": "sqlite",
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
          "exportSubpath": "./sdk",
      "generatedFrom": "/openapi.json",
      "clientClassName": "TodosClient"
    },
    {
      "name": "mcp",
      "kind": "mcp",
      "status": "supported",
      "mcpBin": "todos-mcp",
      "authMode": "api-key"
    },
    {
      "name": "cli",
      "kind": "cli",
      "status": "supported",
      "bin": "todos",
      "authMode": "local-only"
    }
  ]
}
```

- `contractVersion` — the Service Contract version the repo targets (`v1`).
- `kitVersion` — the `@hasna/contracts` version the repo tracks.
- `hosting` — product stories: `user-hosted` and, only when available,
  `hasna-saas`.
- `storage.mode` — active data backend (`sqlite | postgres`), the server's
  internal storage.
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

Storage capabilities use the same waiver pattern in
`metadata.conformance.waivedStorageEngines`; see §6 for the eligibility,
expiry, and `pgTestGate` rules.

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

`runRepoConformance` accepts `env`, `healthSample`, `skipNoCloudScan`,
`manifestTier`, and `now` (the clock used for time-boxed checks such as storage
waiver expiry; defaults to the current time).

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
8. `storage_capabilities` — store-owning cores declare SQLite + PostgreSQL (or
   explicitly waive PostgreSQL), plus `storage.envPrefix` and a live-PG test
   gate unless PostgreSQL is waived; SaaS declares its public PostgreSQL env
   prefix. A waiver never silently excuses an engine: an ineligible waiver on a
   manifest that is otherwise missing the engine is reported as a
   `manifest_valid` error naming the refusal reason, and an ineligible,
   unrecordable, or expired waiver on a manifest that declares both engines
   fails this check.
9. `public_manifest_safety` — public manifests contain no secret or credential
   refs, credential-shaped values, internal hosts, ARNs, or account IDs.
   A credential-shaped KEY whose value is plainly an environment-variable NAME
   is NOT a finding: section 3 requires manifests to reference
   `HASNA_<NAME>_DATABASE_URL` rather than inline a DSN, and flagging the
   compliant behaviour is how a mandatory check gets switched off.
10. `hosting_story` — public OSS cores include the user-hosted product story;
   `saas` repos include the `hasna-saas` story.
11. `mode_enum_compliance` — any `HASNA_<NAME>_STORAGE_MODE` env normalizes to `local|cloud`.
12. `health_shape` — when a serve bin exists, a sampled `/health` payload matches `{ status, version, mode }`.
13. `no_cloud_guard` — no forbidden shared cloud runtime edges (reuses `scanNoCloudTarget`).
14. `published_artifact_gate` — a repo that publishes declares
   `metadata.release.artifactScan.script` and its `prepack` script transitively
   reaches it. See clause C.
15. `credential_seam_compliance` — no source file resolves a Hasna client
   credential by hand. Reading `HASNA_<NAME>_API_KEY` (or the `<NAME>_API_KEY`
   alias) out of `process.env` keeps the stale-snapshot defect that §3a exists
   to remove, so it fails. The rule asks `clientTransportEnvKeys()` for the
   names it polices rather than approximating them, so it cannot drift from the
   seam.

   It also fails a repo that **defines** `resolveClientTransport`,
   `createClientTransport`, `createHasnaHttpTransport`, or
   `resolveStorageClient` itself — a vendored fork of the seam. A fork builds
   its key names by template and reads them through a computed loop, so no
   literal name ever appears and a name-based rule sees nothing: measured, one
   repo scored zero findings while shipping a complete copy of the pre-fix
   resolver on its live storage path. Without this clause the cheapest way to
   turn the gate green is to fork the transport, and the gate would reward the
   exact thing it exists to prevent. Importing and calling those functions is
   the compliant path and never matches.

   It is deliberately narrow, because a mandatory gate that fires on compliant
   code gets switched off — and then it protects nothing, the same end state as
   a check that cannot fail. It matches **read expressions only**: writing the
   variable, naming it in an error message, listing it in a redaction
   allowlist, or forwarding it to a child process are all compliant. Comments
   and JSDoc are masked. Tests, `scripts/`, `dist/`, and shipped `bin/` bundles
   are excluded. Three exclusions are worth stating explicitly, because each was
   measured against the fleet rather than guessed:

   - **Both of the app's OWN key names are policed** — `HASNA_<APP>_API_KEY`
     and the bare `<APP>_API_KEY` alias — because the seam resolves both, so a
     hand-read of either is the same defect. The name list is taken from
     `clientTransportEnvKeys()` unfiltered; narrowing it here would reintroduce
     exactly the drift that function is consulted to prevent. A third-party
     credential that happens to wear an app's name — one repo's
     `RECORDINGS_API_KEY` holds an OpenAI key — clears through a **waiver**,
     which a reviewer reads in the report, rather than through the class going
     unpoliced fleet-wide. Other services' bare aliases stay out of scope: a
     foreign name is only recognised in the namespaced `HASNA_` form.
   - **Top-level inbound surfaces (`src/server/`, `src/http/`, `src/api/`,
     `src/mcp/`) are excluded**, including everything beneath them. A server
     reads its own key to *compare* against a caller's, which is the opposite of
     resolving one to send. The name is identical, so only location can separate
     them — and the location must be TOP-LEVEL. Matching those directory names at
     any depth silently exempted `src/client/api/…`, the most likely place for a
     real client bypass to sit; every measured fleet case is directly under
     `src/`. Widening this requires widening the rule and this clause together.
   - `HASNA_<APP>_SERVE_API_KEY` and `HASNA_<APP>_BOOTSTRAP_API_KEY`, and
     third-party keys wearing the prefix (`HASNA_BRAIN_ANTHROPIC_API_KEY`),
     fall outside the single-segment client-flip grammar and are excluded
     structurally rather than by an allowlist anyone has to maintain.

   The pressure valve is an explicit waiver comment on the read or the line
   above it:

   ```ts
   // hasna-credential-seam-waiver: server-side validation of the inbound key, not a client resolve
   const expected = process.env.HASNA_FACTORY_API_KEY;
   ```

   A waiver with no usable justification is **rejected**, not honoured — it
   would silence the gate while recording nothing a reviewer can weigh. Every
   accepted waiver is echoed into the report, so it stays a thing a human
   reads.

The kit is dev-dependency friendly: `@hasna/contracts` can be a `devDependency`
and the checks run under `bun test` with no runtime footprint in the app.

---

## 10a. Published-artifact clauses

Both clauses below were adopted after a live disclosure, not in anticipation of
one. `@hasna/tenants@0.1.0` was published to the public registry carrying a
complete vendor asset inventory compiled into its build output. The repository
was private and `files: ["dist"]` meant only build output shipped — so the
source file holding the inventory never left the machine while the inventory
itself did. Every source-level review passed. `verify:release` ran typecheck,
tests, and build, and inspected nothing that actually shipped.

### Clause B — No vendor asset inventories in shipped artifacts

**A shipped artifact MUST NOT disclose an inventory of the vendor's assets.**
Domain portfolios, machine inventories, customer lists, internal endpoint
catalogues. In any form, default or not, in any encoding, in source or in build
output.

**What this check is, and is not.** Clause B is a **prohibition**; the check is a
**count**. Those are not the same thing, and the gap is not academic: an
artifact carrying a *small* number of vendor-owned hostnames — below the
threshold — passes. Demonstrated by construction: an artifact built from the 13
files of a real published package that carry owned hostnames (11 distinct,
including two nginx configs and a `bin/` entry point) scans `pass`, exit 0.

The clause still binds. A repo that ships an owned-asset inventory is in breach
whether or not this check fires, and "the scanner passed" is not evidence of
compliance for small-N disclosure. The check exists to make the *bulk* case
mechanically impossible, which is the case that actually happened.

This is distinct from R1, which bans vendor endpoints as *defaults*. R1 is about
what unconfigured software will contact. Clause B is about what shipped bytes
reveal about what the vendor owns — a fact that is disclosed whether or not any
code ever reads it.

Enforced by `scanPublishedArtifact` (`contracts artifact-scan <tarball>`),
which fails when one shipped file carries a bulk inventory of registrable
domains, machine hostnames, public IP addresses, or email addresses.

Three properties of that check are deliberate:

- **It is structural, and it must be.** The obvious guard — a denylist of what
  we own — is the one guard that cannot ship, because the denylist IS the
  disclosure. The scanner therefore does not know which assets are ours. It
  detects the shape, which survives renaming, reformatting, minification, and
  bundling.
- **It cannot pass by having nothing to check.** A target that yields zero
  readable members raises an error rather than reporting a clean verdict, and
  the same rule applies one member at a time: a member the scan could not
  decode is reported and **fails** the scan. There is no size at which a shipped
  file stops being scanned — the biggest member in a tarball is exactly where a
  compiled-in inventory ends up, and a clean verdict over a file nobody read
  would be worse than no scan at all.
- **Its report does not republish what it found.** Findings are counted and
  redacted; scan output is itself an artifact that gets pasted into tasks,
  channels, and CI logs.

**Waivers.** A repo that legitimately ships public reference data — a
public-suffix list, an ICANN TLD table — declares
`metadata.conformance.waivedAssetInventories` with `reason` naming the data,
`reviewedBy`, and `expiresAt`. **An inventory of assets the vendor owns is never
eligible**, at any threshold, in any encoding. A waiver suppresses the failure
and keeps the finding on the record; it never erases it.

The gate READS that declaration: `contracts artifact-scan <tarball>` loads
`./hasna.contract.json` (or `--manifest <file>`) and applies the waivers still
in force. `expiresAt` is enforced there, so the time-boxing is a property rather
than a promise — an expired waiver stops applying on its own, and a waiver
missing `reason` or `reviewedBy` never applied in the first place. A documented
escape hatch that the enforcement does not read is not an escape hatch; it
leaves a compliant repo no recourse but to unwire the gate.

**Measured, not asserted.** Against the real disclosed artifact
(`@hasna/tenants@0.1.0`, 178 names compiled into `dist/`) the scanner detects
**94.4%**, in the quoted-array form it actually shipped and in markdown,
numbered-list, YAML and bare-line renderings of the same data. Against eleven
Hasna packed artifacts and against `zod`, `email-validator`, `commander` and
`typescript` it reports nothing; against `nodemailer`, `validator` and
`class-validator` it reports their genuine reference tables — the waiver case.
A 20,414-member package scans in **5.9 s**.

**Stated limits.** All measured, none theoretical:

- Detection rests on IANA's TLD list minus a small set that collides with
  Hasna's own `<noun>.<verb>` operation grammar (`tasks.next`,
  `credential.read`, `service.health`) and with common filenames. Each exclusion
  is backed by an observed false positive and each is a **deliberate blind
  spot**: an inventory built only from those TLDs is not detected by count.
- **In code members, a run of one brand across many TLDs written one per line
  and unquoted is not counted** — that shape is indistinguishable from property
  access on one receiver (`exports.vi`, `exports.ua`, … are all ccTLDs). Quoted
  and array forms in code ARE counted, as are all unquoted forms in prose and
  tabular members.
- Runtime string concatenation, IDN/punycode spellings, and reversed or
  otherwise transformed encodings beyond one level of base64/hex are not
  detected by a static scan.
- The gate binds `prepack`, which `npm publish --ignore-scripts` skips. Nothing
  in a package can defend against the publisher choosing not to run its own
  hooks; that is a release-process control, not a code one.
- **IPv4 is read only from values** — whole quoted literals, or bare tokens in
  non-code members — in **presentation format**, and never under a version key
  (`v8`, `node`, `chrome`, `engineVersion`, …). Reading raw text matched SVG
  path coordinates in minified bundles; accepting zero-padded quads turned
  latin1-decoded binaries into findings; and four-component version strings are
  numerically indistinguishable from addresses, so `playwright` and
  `node-releases` both failed on bundled version tables. A machine list keyed
  with a version word is the residual, and it is narrow: address spellings
  (`ipAddress`, `public_ip`, `PublicIpAddress`, `ansible_host`, …) all count.
- **Binary members still yield roughly one spurious address per 22 MB** once
  decoded as latin1. That is far below the per-file threshold, but the
  artifact-wide union reaches it at around 450 MB of shipped binary — inside
  the scan window. An artifact that large should declare an `ip` waiver rather
  than have the gate loosened.

Clause B is a prohibition, not a count: it binds whether or not the guard can
see the violation.

### Clause C — Published-artifact scanning is a hard release gate

**Every repo that publishes MUST scan its PACKED artifact, and the scan MUST be
bound to `prepack`.**

`prepack`, not `verify:release`, and the distinction is the entire point: a hook
a publisher can step around by running `npm publish` directly is not a hook.
`prepack` is the one lifecycle script that both `npm pack` and `npm publish`
always run.

The scan MUST run against the **packed tarball**, never `src/`. `files`
negations mean repo and package diverge, and the divergence is exactly where a
disclosure hides.

Declare the script in the manifest and wire it into `prepack`:

```json
{ "metadata": { "release": { "artifactScan": { "script": "scan:artifact" } } } }
```

```json
{ "scripts": {
    "prepack": "bun run verify:release",
    "verify:release": "bun test && bun run scan:artifact",
    "scan:artifact": "bun scripts/scan-artifact.ts"
} }
```

`published_artifact_gate` then resolves the real script graph — it does not grep
`prepack` for a blessed command name, which would pass for any repo that wrote
the magic string in a comment. Invoke the kit through its **package bin**
(`contracts artifact-scan`, or `bunx @hasna/contracts@<version> artifact-scan`),
not by executing a file inside `dist/` directly. **Pin the version**: an
unpinned `bunx`/`npx` resolves to whatever is newest at publish time, so the
gate's own behaviour is not reproducible and a resolution failure becomes a
silent non-run. The check fails on an unpinned invocation.

**Predicate.** The repo publishes — that is, `package.json` is not
`private: true`. A private package skips the check; there is no artifact to gate.

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

## 12. Migration from pre-0.8.3 manifests

The deployment-placement field is **rejected, not ignored**: a manifest that
still carries it — top-level or on a service surface, in any spelling — fails
validation with an error naming the field, and `storage.mode` accepts only
`sqlite | postgres`. Migration is deletion plus rename: delete the placement
arrays, rename `storage.mode` values (the old file-backed value becomes
`sqlite`, the old server-backed value becomes `postgres`). Missing `hosting`
and `serviceSurfaces` still receive compatible defaults. The current schema
intentionally rejects a declared non-`.db` `storage.sqlitePath`, a SaaS store
without `storage.envPrefix`, and a declared supported API that omits the
health/readiness/version endpoints or uses a method other than `GET`.

Conformance is stricter than schema parsing. A legacy service manifest can
remain schema-valid while failing new checks until it:

1. declares the class-appropriate surfaces: CLI for a CLI-only
   `cli-with-store`, or API, SDK, MCP, and CLI for service-capable repos;
2. declares `GET /health`, `GET /ready`, and `GET /version` for each supported
   service API;
3. points SDK declarations at real package exports;
4. declares SQLite + PostgreSQL capabilities, `storage.envPrefix`, and a
   `pgTestGate` where required, or records an explicit
   `waivedStorageEngines` exception for a SQLite-only `cli-with-store` — a
   repo adopting the waiver SHOULD keep an existing `storage.envPrefix`, since
   the waiver only removes the requirement and deleting the field discards the
   declared `HASNA_<NAME>_DATABASE_URL` contract;
5. adds a root operator-deploy artifact (`docker-compose.yml`) when it ships
   a service; and
6. removes private infrastructure references from the public manifest.

Conformance treats `pgTestGate.command` and every other manifest command as
data only; it never executes them.

These additive v1 capability declarations do not consume the separately
planned `hasna.service_contract.v2`. V2 remains reserved for breaking API-base,
operation-registry, authorization, worker, and deployment-control-plane
semantics.
