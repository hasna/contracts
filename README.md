# @hasna/contracts

Side-effect-free generic contract primitives for Hasna packages.

The `1.0.0-rc.1` boundary contains only Zod schemas, inferred TypeScript types,
validators, fixtures, and JSON Schemas. It has no database auth, HTTP/storage
client, filesystem scanner, CLI, source generator, SDK generator, or product
operation implementation.

```bash
bun add --exact @hasna/contracts@1.0.0-rc.1
```

```ts
import {
  CORE_SCHEMA_IDS,
  EventEnvelopeSchema,
  parseCoreContract,
  type EventEnvelope,
} from "@hasna/contracts";

const event: EventEnvelope = EventEnvelopeSchema.parse(input);
parseCoreContract(CORE_SCHEMA_IDS.eventEnvelope, event);
```

The generic primitives cover errors, principals and tenant context,
idempotency, event envelopes, blob and secret references, compatibility, and
operation/capability descriptors. Their immutable IDs and JSON Schema files
are listed in [the release-candidate guide](docs/CORE_RELEASE_CANDIDATE.md).

JSON Schemas are importable without executing a generator:

```ts
import eventEnvelopeSchema from
  "@hasna/contracts/json-schemas/event-envelope.json" with { type: "json" };
```

Runtime helpers moved to exact-pinned owner packages:

- `@hasna/contracts-auth@1.0.0-rc.1`
- `@hasna/contracts-client@1.0.0-rc.1`
- `@hasna/contracts-vendor-kit@1.0.0-rc.1`
- `@hasna/contracts-sdk-generator@1.0.0-rc.1`
- `@hasna/contracts-cli@1.0.0-rc.1`

Mailery product operations remain in `hasna/mailery`; this package defines only
the generic descriptor vocabulary.

## Verification

```bash
bun run schemas:check
bun run typecheck
bun run test
bun run matrix:compile
bun run candidate:verify
```

The candidate archive, digest, SPDX SBOM, and provenance are reproducibly
generated under `release/1.0.0-rc.1`.
