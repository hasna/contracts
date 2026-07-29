import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  CORE_SCHEMA_IDS,
  CORE_SCHEMA_REGISTRY,
  CapabilityDescriptorSchema,
  EventEnvelopeSchema,
  IdempotencySchema,
  SecretRefSchema,
  TenantContextSchema,
  parseCoreContract,
  validateEmbeddedCoreContract,
} from "../src/primitives";

const root = join(import.meta.dir, "..");
const digest = `sha256:${"a".repeat(64)}`;
const principal = {
  schema: CORE_SCHEMA_IDS.principal,
  id: "service:test",
  kind: "service",
  tenantId: "tenant-test",
};

describe("generic core primitives", () => {
  test("schema ids are immutable, unique, and match every checked-in JSON Schema", () => {
    expect(Object.isFrozen(CORE_SCHEMA_IDS)).toBe(true);
    expect(Object.isFrozen(CORE_SCHEMA_REGISTRY)).toBe(true);
    expect(new Set(Object.values(CORE_SCHEMA_IDS)).size).toBe(Object.keys(CORE_SCHEMA_IDS).length);

    const bundle = JSON.parse(readFileSync(join(root, "schemas/v1/bundle.json"), "utf8")) as {
      schemas: Record<string, { $id: string }>;
    };
    expect(Object.keys(bundle.schemas).sort()).toEqual(Object.values(CORE_SCHEMA_IDS).sort());
    for (const schemaId of Object.values(CORE_SCHEMA_IDS)) {
      expect(bundle.schemas[schemaId]?.$id).toBe(schemaId);
    }
  });

  test("accepts additive N and N-1 principal fixtures", () => {
    for (const fixture of ["n-minus-one.principal.valid.json", "n.principal.valid.json"]) {
      const value = JSON.parse(readFileSync(join(root, "fixtures/compatibility", fixture), "utf8"));
      expect(parseCoreContract(CORE_SCHEMA_IDS.principal, value).id).toBeString();
    }
  });

  test("validates a declarative capability without registering an implementation", () => {
    const value = JSON.parse(
      readFileSync(join(root, "fixtures/compatibility/n.capability.valid.json"), "utf8"),
    );
    expect(CapabilityDescriptorSchema.parse(value).operations[0]?.effect).toBe("none");
    expect(validateEmbeddedCoreContract(value).success).toBe(true);
  });

  test("binds tenant, principal, idempotency, and event context", () => {
    const tenant = {
      schema: CORE_SCHEMA_IDS.tenantContext,
      tenantId: "tenant-test",
      principal,
      requestId: "request-test",
    };
    expect(TenantContextSchema.safeParse(tenant).success).toBe(true);
    expect(TenantContextSchema.safeParse({ ...tenant, tenantId: "other" }).success).toBe(false);

    const idempotency = {
      schema: CORE_SCHEMA_IDS.idempotency,
      key: "idempotency-test",
      operationId: "example.echo.invoke",
      requestDigest: digest,
      createdAt: "2026-07-29T00:00:00.000Z",
      expiresAt: "2026-07-30T00:00:00.000Z",
    };
    expect(IdempotencySchema.safeParse(idempotency).success).toBe(true);
    expect(
      IdempotencySchema.safeParse({ ...idempotency, expiresAt: "2026-07-28T00:00:00.000Z" }).success,
    ).toBe(false);
    expect(EventEnvelopeSchema.safeParse({
      schema: CORE_SCHEMA_IDS.eventEnvelope,
      specVersion: "1.0",
      id: "event-test",
      type: "example.echoed",
      source: "https://example.invalid/producer",
      time: "2026-07-29T00:00:00.000Z",
      tenant,
      principal,
      idempotency,
      data: { ok: true },
    }).success).toBe(true);
  });

  test("SecretRef is reference-only and strict", () => {
    const reference = {
      schema: CORE_SCHEMA_IDS.secretRef,
      uri: "vault://example/application-key",
      purpose: "Synthetic fixture",
    };
    expect(SecretRefSchema.safeParse(reference).success).toBe(true);
    expect(SecretRefSchema.safeParse({ ...reference, value: "must-not-be-accepted" }).success).toBe(false);
  });
});
