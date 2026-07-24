import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  TODOS_CANONICAL_CAPABILITY_IDS,
  TODOS_CONTRACT_DIGEST,
  TODOS_ERROR_CODES,
  TODOS_ERROR_CATALOG,
  TODOS_OPERATION_MANIFEST_DIGEST,
  TodosAuthorityConfigSchema,
  TodosAuthorityHandshakeSchema,
  TodosCanonicalAuthorityHandshakeSchema,
  TodosIdentityContextSchema,
  TodosModeSchema,
  createTodosError,
  validateCanonicalTodosAuthorityHandshake,
  validateTodosIdentityContext,
} from "../../src/todos";

const generatedRoot = join(import.meta.dir, "..", "..", "generated", "todos", "v1");

function fixture(path: string): unknown {
  return JSON.parse(readFileSync(join(generatedRoot, "fixtures", path), "utf8"));
}

describe("Todos mode and authority", () => {
  test("accepts exactly local and cloud", () => {
    expect(TodosModeSchema.parse("local")).toBe("local");
    expect(TodosModeSchema.parse("cloud")).toBe("cloud");

    for (const value of [
      undefined,
      null,
      "",
      {},
      "remote",
      "self_hosted",
      "self-hosted",
      "hybrid",
    ]) {
      expect(TodosModeSchema.safeParse(value).success).toBe(false);
    }
  });

  test("requires explicit mode and exactly one authority", () => {
    const local = fixture("authority.local.valid.json");
    const cloud = fixture("authority.cloud.valid.json");
    expect(TodosCanonicalAuthorityHandshakeSchema.safeParse(local).success).toBe(true);
    expect(TodosCanonicalAuthorityHandshakeSchema.safeParse(cloud).success).toBe(true);
    expect(local).not.toHaveProperty("local_fallback");
    expect(cloud).not.toHaveProperty("local_fallback");

    const withoutMode = structuredClone(local) as Record<string, unknown>;
    delete withoutMode.mode;
    expect(TodosAuthorityConfigSchema.safeParse(withoutMode).success).toBe(false);

    const inferredFromEndpoint = structuredClone(cloud) as Record<string, unknown>;
    delete inferredFromEndpoint.mode;
    expect(TodosAuthorityConfigSchema.safeParse(inferredFromEndpoint).success).toBe(false);

    const multiple = {
      ...(local as Record<string, unknown>),
      authorities: [
        (local as { authority: unknown }).authority,
        (cloud as { authority: unknown }).authority,
      ],
    };
    expect(TodosAuthorityConfigSchema.safeParse(multiple).success).toBe(false);

    const mismatchedHandshake = {
      ...(local as Record<string, unknown>),
      authority: (cloud as { authority: unknown }).authority,
    };
    expect(TodosAuthorityHandshakeSchema.safeParse(mismatchedHandshake).success).toBe(false);
  });

  test("fails closed on wrong digests and missing, extra, reordered, or invented capabilities", () => {
    const local = fixture("authority.local.valid.json") as Record<string, unknown>;
    expect(local.contractDigest).toBe(TODOS_CONTRACT_DIGEST);
    expect(local.manifestDigest).toBe(TODOS_OPERATION_MANIFEST_DIGEST);
    expect(local.capabilityIds).toEqual(TODOS_CANONICAL_CAPABILITY_IDS);

    const canonicalCapabilities = [...TODOS_CANONICAL_CAPABILITY_IDS];
    const attacks = [
      { ...local, contractDigest: "0".repeat(64) },
      { ...local, manifestDigest: "1".repeat(64) },
      { ...local, capabilityIds: canonicalCapabilities.slice(1) },
      { ...local, capabilityIds: [...canonicalCapabilities, "invented-capability"] },
      { ...local, capabilityIds: [...canonicalCapabilities].reverse() },
      {
        ...local,
        capabilityIds: canonicalCapabilities.map((id, index) => (
          index === 0 ? "invented-capability" : id
        )),
      },
    ];
    for (const attack of attacks) {
      expect(TodosCanonicalAuthorityHandshakeSchema.safeParse(attack).success).toBe(false);
      expect(validateCanonicalTodosAuthorityHandshake(attack)).toBe(false);
    }
  });

  test("authority implementation is data-only", () => {
    for (const name of ["authority.ts", "canonical-authority.ts"]) {
      const source = readFileSync(join(import.meta.dir, "..", "..", "src", "todos", name), "utf8");
      expect(source).not.toContain("process.env");
      expect(source).not.toContain("Bun.env");
      expect(source).not.toContain("Deno.env");
    }
  });
});

describe("Todos identity context", () => {
  test("validates issuer, audience, tenant binding, roles, scopes, and request context", () => {
    const identity = fixture("identity.valid.json");
    expect(TodosIdentityContextSchema.safeParse(identity).success).toBe(true);
    expect(TodosIdentityContextSchema.safeParse(fixture("identity.invalid.json")).success).toBe(false);

    const invalidAudience = {
      ...(identity as Record<string, unknown>),
      audience: "platform_operator",
    };
    expect(TodosIdentityContextSchema.safeParse(invalidAudience).success).toBe(false);

    const invalidAdminRole = {
      ...(identity as Record<string, unknown>),
      audience: "tenant_admin",
      roles: ["customer_member"],
    };
    expect(TodosIdentityContextSchema.safeParse(invalidAdminRole).success).toBe(false);
  });

  test("enforces audience, scope, tenant, and idempotency requirements", () => {
    const identity = fixture("identity.valid.json");
    const accepted = validateTodosIdentityContext(identity, {
      organizationId: "tenant-a",
      tenantId: "tenant-a",
      audience: "customer",
      requiredScopes: ["todos:tasks:write"],
      requireIdempotencyKey: true,
    });
    expect(accepted.success).toBe(true);

    const tenantMismatch = validateTodosIdentityContext(identity, {
      organizationId: "tenant-b",
      tenantId: "tenant-b",
      audience: "customer",
      requiredScopes: ["todos:tasks:read"],
    });
    expect(tenantMismatch.success).toBe(false);
    if (!tenantMismatch.success) {
      expect(tenantMismatch.error.code).toBe("TODOS_TENANT_MISMATCH");
    }

    const missingScopeIdentity = {
      ...(identity as Record<string, unknown>),
      scopes: ["todos:projects:read"],
    };
    const missingScope = validateTodosIdentityContext(missingScopeIdentity, {
      organizationId: "tenant-a",
      tenantId: "tenant-a",
      audience: "customer",
      requiredScopes: ["todos:tasks:write"],
    });
    expect(missingScope.success).toBe(false);
    if (!missingScope.success) {
      expect(missingScope.error.code).toBe("TODOS_SCOPE_REQUIRED");
    }
  });
});

describe("Todos typed errors", () => {
  test("ships one unique canonical vocabulary with transport status as metadata", () => {
    expect(new Set(TODOS_ERROR_CODES).size).toBe(TODOS_ERROR_CODES.length);
    expect(TODOS_ERROR_CATALOG.map((entry) => entry.code)).toEqual([...TODOS_ERROR_CODES]);
    expect(TODOS_ERROR_CATALOG.every((entry) => entry.transportStatus >= 100 && entry.transportStatus <= 599)).toBe(true);

    const error = createTodosError("TODOS_NOT_FOUND", "Task was not found");
    expect(error.code).toBe("TODOS_NOT_FOUND");
    expect(error).not.toHaveProperty("httpStatus");

    const internal = createTodosError("TODOS_INTERNAL", "Unexpected failure");
    expect(internal.retryable).toBe(true);
  });
});
