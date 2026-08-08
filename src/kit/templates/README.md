# Vendored Hasna storage kit

**Generated — do not edit.** This directory is stamped into the repo by
[`@hasna/contracts`](https://github.com/hasna/contracts) and verified in CI.

- Regenerate: `bunx @hasna/contracts vendor-kit`
- Verify (CI): `bunx @hasna/contracts vendor-kit --check` — fails on stale or hand-edited files.

## What it is

A canonical Postgres storage kit shared across the Hasna fleet:

| File            | Purpose                                                              |
| --------------- | ------------------------------------------------------------------- |
| `backend.ts`    | Server backend + `DATABASE_URL` resolution (`sqlite` \| `postgresql`) |
| `tls.ts`        | The one correct TLS approach (libpq `sslmode` semantics + RDS CA)    |
| `pool.ts`       | `pg.Pool` factory with fleet-standard TLS                            |
| `query.ts`      | Typed query wrapper (`query` / `many` / `get` / `one` / `execute`)   |
| `migrations.ts` | `schema_migrations` ledger with sha256 checksums                     |
| `health.ts`     | `checkHealth` (SELECT 1) and `checkReady` (migrated?) probes         |

## PURE REMOTE (Amendment A1)

Cloud mode = reads **and** writes go directly to cloud Postgres. This kit
contains **no sync engine, no cache-as-mode, and no merge logic**. In `local`
mode there is no Postgres pool at all; SQLite is authoritative.

## TLS

`resolveTlsConfig` in `tls.ts` turns the DSN's TLS parameters into an explicit
`ssl` option, and `pool.ts` hands `pg` the DSN with those parameters **stripped**
(`connectionStringWithoutTlsParameters`). The strip is what makes the resolved
object real: `pg` re-parses `connectionString` after merging pool options and lets
the parse win, so a surviving `sslmode`, `ssl`, `sslcert`, `sslkey`, `sslrootcert`,
`sslpassword`, `sslnegotiation` or `uselibpqcompat` would replace everything
resolved here — CA bundle included. The full history is in the `tls.ts` header.

### The mode table — what reaches the socket

| DSN | `resolveTlsConfig` returns | At the socket |
| --- | --- | --- |
| `?sslmode=disable`, or `?ssl=` with `0` / `false` / `no` / `off` / `disable` | `false` | Plaintext, stated explicitly. An ambient `PGSSLMODE` **cannot** override it. |
| no `ssl` parameter at all | `undefined` | No `ssl` key is set, so `pg` falls back to `PGSSLMODE`. This is libpq's documented behaviour and is deliberate. |
| `?sslmode=prefer` / `require` / `allow`, `?ssl=` with `1` / `true` / `yes` / `on` / `require`, or `?sslnegotiation=direct` | `{rejectUnauthorized: true, ca?}` | Encrypt **and** verify. A CA bundle is pinned when one is available; without one, Node's trust store applies. |
| `?sslmode=verify-ca` / `verify-full` | `{rejectUnauthorized: true, ca}` | Encrypt **and** verify against the bundle. A bundle is **mandatory** — `resolveTlsConfig` throws when none is found, so verification cannot silently downgrade. |
| `?sslmode=` with any other value, **including an empty or whitespace-only one** | — | Throws `Unknown sslmode '<value>'`, naming the accepted set. |

**An empty `?sslmode=` is a value, not an absence, and it does not fall on the
"no `ssl` parameter" row.** The parameter is present, so the DSN made a
statement; an empty statement is not a request for the default. This is libpq's
own reading — `psql "…?sslmode="` fails with `invalid sslmode value: ""`, the
same error and the same line as `invalid sslmode value: "bogus"`, while a DSN
with the parameter absent gets through to the socket. Until row `feb638fa` the
kit resolved empty exactly like absent, so `?sslmode=${PGSSLMODE}` with the
variable unset silently handed the decision to the environment; to defer to
`PGSSLMODE`, leave the parameter out entirely.

`allow` maps to `prefer`. `sslnegotiation` is carried forward as an explicit pool
option instead of being dropped with the other stripped parameters, and
`sslcert` / `sslkey` / `sslpassword` are read out of the DSN into the resolved
object, since `pg` no longer sees any of them.

`prefer` and `require` verify because that is what the socket has always done —
`pg` says so on stderr: *"SECURITY WARNING: The SSL modes 'prefer', 'require', and
'verify-ca' are treated as aliases for 'verify-full'."* Nothing that connected
before stops connecting; connections that were failing against a private CA start
working.

### `false` and `undefined` are different answers

`pool.ts` sets `config.ssl` only when the resolved value is not `undefined`, and
`pg` reads `process.env.PGSSLMODE` only when no `ssl` key is present. So an
explicit operator "off" resolves to `false` and wins, while a DSN that expressed no
policy at all resolves to `undefined` and defers.

Collapsing the two is a regression in whichever direction it is done. Returning
`undefined` for an explicit off lets an ambient `PGSSLMODE` open TLS to a host the
operator asked to reach in plaintext. Returning `false` for a bare DSN reads as the
tidier fix and silently downgrades an operator who set `PGSSLMODE=require` to force
TLS on. `tests/kit-tls-handshake.test.ts` pins both halves against real handshakes,
so neither can drift.

### CA bundles

Discovered in priority order:

1. an explicit `ca` string passed by the caller,
2. an explicit `caCertPath` passed by the caller,
3. `sslrootcert` in the connection string,
4. `PGSSLROOTCERT`,
5. `NODE_EXTRA_CA_CERTS`.

The Amazon RDS global bundle is at
<https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem>. RDS needs it:
its root is not in Node's trust store.

**A supplied bundle REPLACES the default trust store rather than adding to it.**
That is Node's `ca` option, not a kit choice. Under `prefer` and `require` this
means a `PGSSLROOTCERT` or `NODE_EXTRA_CA_CERTS` set for some unrelated purpose
becomes the connection's only trust anchor. It is tighter than having no bundle,
not looser, and the one case where a working connection can stop is a **public-CA**
managed Postgres reached from a host carrying an ambient extra CA — the server's
real root is then no longer trusted. Add that root to the bundle, or point
`sslrootcert` at the right file for that connection.

## Peer dependency

Requires `pg` (and `@types/pg` for TypeScript) in the host repo.
