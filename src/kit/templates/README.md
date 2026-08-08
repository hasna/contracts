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

`resolveTlsConfig` in `tls.ts` **returns** a config shaped by libpq `sslmode`
semantics:

- `require` — encrypt, do not verify (RDS default without a bundle)
- `verify-ca` / `verify-full` — encrypt **and** verify against a CA bundle
  (mandatory; throws if none is available)

### ⚠ That is what the function returns, not what reaches the socket

`pool.ts` hands `pg` both the `connectionString` and that `ssl` object, and `pg`
re-parses the connection string with the parsed result winning. Any SSL query
parameter in the DSN (`sslmode`, `ssl`, `sslcert`, `sslkey`, `sslrootcert`)
makes `pg` reset `ssl` to `{}` — **discarding the object above, CA bundle
included**. `rejectUnauthorized` is then undefined and Node's default (`true`)
applies.

Measured against real TLS handshakes on pg 8.22.0 **and** pg 8.13.1 (the
declared floor), node 22.22.3:

| DSN | kit returned | pg computed | outcome at the socket |
| --- | --- | --- | --- |
| `?sslmode=require`, no CA, self-signed server | `{rejectUnauthorized:false}` | `{}` | `DEPTH_ZERO_SELF_SIGNED_CERT` — **it verified** |
| `?sslmode=require`, CA supplied, private-CA server | `{rejectUnauthorized:false, ca}` | `{}` | `UNABLE_TO_VERIFY_LEAF_SIGNATURE` — **CA discarded** |
| `?sslmode=verify-full`, CA supplied, private-CA server | `{rejectUnauthorized:true, ca}` | `{}` | `UNABLE_TO_VERIFY_LEAF_SIGNATURE` — **CA discarded** |

`pg` states it on stderr itself: *"SECURITY WARNING: The SSL modes 'prefer',
'require', and 'verify-ca' are treated as aliases for 'verify-full'."*

So `require` is **stricter** than documented, and `verify-ca` / `verify-full`
are **broken** when the CA arrives via `ca` / `caCertPath` / `PGSSLROOTCERT` /
`NODE_EXTRA_CA_CERTS` — that bundle never reaches `pg`, so a private-CA server
(Amazon RDS included) fails to connect while the docs say verification is
configured.

Until that is fixed, the working way to verify against a private CA is to put
the path in the DSN itself, where `pg` reads it:
`?sslmode=verify-full&sslrootcert=/path/to/global-bundle.pem` — measured
connecting against a private-CA server, and correctly refusing a self-signed
one.

Point `PGSSLROOTCERT` at the Amazon RDS global bundle:
<https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem> — but note
it is currently discarded whenever the DSN carries an SSL parameter.

The fix is a behaviour change and is tracked separately (todos `3dee42b0`):
strip the TLS query parameters from the DSN in `pool.ts` after resolving them.
`hasna/emails` already does this in its forked kit and is measured working.

## Peer dependency

Requires `pg` (and `@types/pg` for TypeScript) in the host repo.
