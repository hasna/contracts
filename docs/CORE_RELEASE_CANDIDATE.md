# Contracts 1.0 release-candidate boundary

`@hasna/contracts@1.0.0-rc.1` is a major boundary. Its root and every exported
subpath are data-only: Zod schemas, inferred TypeScript types, validators, and
checked-in JSON Schemas. Importing core does not inspect the filesystem or
environment, open a network or database connection, register a CLI, or write
source code.

The v1 generic schema IDs are immutable:

| Primitive | Schema ID |
| --- | --- |
| Error | `hasna.contracts.error.v1` |
| Principal | `hasna.contracts.principal.v1` |
| Tenant context | `hasna.contracts.tenant_context.v1` |
| Idempotency | `hasna.contracts.idempotency.v1` |
| Event envelope | `hasna.contracts.event_envelope.v1` |
| Blob reference | `hasna.contracts.blob_ref.v1` |
| Secret reference | `hasna.contracts.secret_ref.v1` |
| Compatibility | `hasna.contracts.compatibility.v1` |
| Operation descriptor | `hasna.contracts.operation_descriptor.v1` |
| Capability descriptor | `hasna.contracts.capability_descriptor.v1` |

The TypeScript registry is `CORE_SCHEMA_REGISTRY`; JSON files are exported at
`@hasna/contracts/json-schemas/*.json`. Runtime refinements named by
`x-hasna-runtime-validator` must still be run with `validateCoreContract`.
Breaking shapes get a new schema ID. Existing IDs are never repointed.

## Ownership split

The former runtime helpers are release-independent packages:

| Removed core surface | Owner package |
| --- | --- |
| `@hasna/contracts/auth` | `@hasna/contracts-auth@1.0.0-rc.1` |
| `@hasna/contracts/client` | `@hasna/contracts-client@1.0.0-rc.1` |
| `@hasna/contracts/vendor-kit` | `@hasna/contracts-vendor-kit@1.0.0-rc.1` |
| `@hasna/contracts/sdk` | `@hasna/contracts-sdk-generator@1.0.0-rc.1` |
| `contracts` binaries | `@hasna/contracts-cli@1.0.0-rc.1` |

Product operation manifests are not core primitives. Mailery operations and
their request/response schemas remain owned and released by `hasna/mailery`.
The synthetic `example.echo` compatibility fixture is schema test data, not a
shipped operation implementation or product capability.

## Exact-pin migration and rollback

1. Before migration, replace every range with the exact legacy pin
   `@hasna/contracts: "0.8.4"`. Do not admit this major through `^`, `~`, or a
   workspace wildcard.
2. Classify imports using
   [`reverse-dependencies.json`](release/reverse-dependencies.json). Replace
   runtime imports with the exact `1.0.0-rc.1` owner package shown above.
3. Move product descriptors into their product repository. Import only generic
   primitive schemas and types from `@hasna/contracts: "1.0.0-rc.1"`.
4. Compile the N, N-1, and split-owner fixtures with `bun run matrix:compile`,
   then run the consumer's own suite before changing its lockfile.
5. Roll back by restoring the consumer lockfile and the exact `0.8.4` pin.
   Never publish a compatibility alias from core and never reuse a v1 schema ID
   for a rollback shape.

The public reverse-dependency inventory is a gate checklist. Consumers whose
source is private or unavailable—including the required Mailery producer—must
add their own exact-pin compile result before the `next` tag can move to
`latest`.

## Candidate evidence

`bun run candidate:build` creates a normalized tarball plus SHA-256, SPDX SBOM,
and SLSA-shaped provenance under `release/1.0.0-rc.1`. The archive uses sorted
paths, uid/gid zero, epoch timestamps, and gzip without a timestamp.
`bun run candidate:verify` independently rebuilds those bytes and fails on any
hash or metadata drift.
