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

`self_hosted` at the docs tier maps to the **`cloud` runtime mode** pointed at a
private database URL. It is not a distinct runtime.

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

The words `remote`, `hybrid`, and `self_hosted` are accepted **only as
deprecated aliases** that normalize to `cloud`. The `hasna.contract.json`
manifest and every wire schema reject them; only the runtime env normalizer
(`normalizeStorageMode`, `src/mode.ts`) tolerates them and emits a deprecation
warning.

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

## 6. SQLite path and secret ref conventions

- **Local SQLite path:** `~/.hasna/<name>/<name>.db`.
- **Cloud database secret ref (Secrets Manager):** `hasna/oss/<name>/database-url`.

Apps read the secret ref only through their secret store; the resolved URL is
supplied to the app as `HASNA_<NAME>_DATABASE_URL` at runtime and is never baked
into an image or committed.

---

## 7. Self-host artifact

Every `service` and `saas` repo **MUST** ship a `docker-compose.yml` at the repo
root as the canonical self-host artifact. It brings up an app-owned Postgres and
the app in `cloud` mode pointed at it. See this repo's `docker-compose.yml` for
the reference template.

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
- If `storage.mode` is `local`, **MUST** set `storage.sqlitePath`
  (`~/.hasna/<name>/<name>.db`).
- **MUST** ship the `<name>` bin.
- SHOULD ship a `<name>-mcp` bin for agent access.

### `service`
A long-running HTTP/MCP service.
- **MUST** declare `storage`.
- **MUST** ship a `<name>-serve` bin and expose `/health`, `/ready`, `/version`.
- **MUST** ship a root `docker-compose.yml`.
- SHOULD ship a `<name>-mcp` bin.

### `saas`
A Hasna-operated managed service.
- **MUST** declare `storage` with `storage.mode` = `cloud`.
- **MUST** set `storage.databaseUrlSecretRef` (`hasna/oss/<name>/database-url`).
- **MUST** ship a `<name>-serve` bin and expose `/health`, `/ready`, `/version`.
- **MUST** ship a root `docker-compose.yml` for parity/self-host.

All classes **MUST** pass the no-cloud guard: no dependency on a shared cloud
runtime (`FORBIDDEN_SHARED_CLOUD_RUNTIMES`). App-owned cloud is declared per app
via `AppCloudManifest`; it is never a shared runtime import.

---

## 9. `hasna.contract.json`

Each repo root carries a `hasna.contract.json`:

```json
{
  "$schema": "./node_modules/@hasna/contracts/dist/hasna.contract.schema.json",
  "schema": "hasna.service_contract.v1",
  "name": "todos",
  "class": "cli-with-store",
  "contractVersion": "v1",
  "kitVersion": "0.3.0",
  "bins": ["todos", "todos-mcp", "todos-serve"],
  "storage": {
    "mode": "cloud",
    "envPrefix": "HASNA_TODOS_",
    "aliasEnvPrefix": "TODOS_",
    "databaseUrlSecretRef": "hasna/oss/todos/database-url",
    "sqlitePath": "~/.hasna/todos/todos.db"
  }
}
```

- `contractVersion` — the Service Contract version the repo targets (`v1`).
- `kitVersion` — the `@hasna/contracts` version the repo tracks.

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
4. `mode_enum_compliance` — any `HASNA_<NAME>_STORAGE_MODE` env normalizes to `local|cloud`.
5. `health_shape` — when a serve bin exists, a sampled `/health` payload matches `{ status, version, mode }`.
6. `no_cloud_guard` — no forbidden shared cloud runtime edges (reuses `scanNoCloudTarget`).

The kit is dev-dependency friendly: `@hasna/contracts` can be a `devDependency`
and the checks run under `bun test` with no runtime footprint in the app.

---

## 11. Secure local-store lifecycle

The shared secure local-store policy is `hasna.secure_local_store_policy.v1`
(`SecureLocalStorePolicySchema`) and the helper module is
`@hasna/contracts/secure-local-store`.

This policy applies to local operator state under `.hasna` and `.codewith`.
The default inventory is explicit by package: Codewith, Todos, Conversations,
Mementos, Knowledge, Projects, Browser, Terminal, Logs, and Loops.

Local stores **MUST** use owner-only defaults:

- Store directories: `0700`.
- Store files: `0600`.
- SQLite main DB files, WAL sidecars, and SHM sidecars: `0600`.
- Backup, export, report, session, snapshot, tmp, and log artifacts: `0600`
  unless a package records a narrower non-secret exception.

Lifecycle cleanup **MUST** default to dry-run. Destructive retention requires:

1. Explicit apply intent.
2. A package-owned retention adapter.
3. Artifact allowlist matches; no broad delete outside the allowlist.
4. Active-record exclusion proof for current tasks, sessions, messages, runs,
   workspace rows, attachments, evidence, or other package-owned references.
5. Redaction-before-persistence and redacted evidence from the owning package.

SQLite maintenance **MUST NOT** run against active stores. WAL checkpoint,
incremental vacuum, optimize, or vacuum operations are allowed only when the
caller explicitly proves exclusive/offline access for that package store. The
contracts helper plans maintenance and can apply it only when the caller opts in
to both apply mode and SQLite maintenance.

The CLI surface:

```bash
contracts secure-local-store --json
contracts secure-local-store "$HOME" --json --plan --store todos
contracts secure-local-store "$HOME" --json --apply --store todos
contracts secure-local-store "$HOME" --json --plan --retention --store todos --retention-proof todos-exports-backups
```

The CLI and helper report paths, modes, counts, statuses, store ids, and adapter
ids only. They do not read or print file contents.
