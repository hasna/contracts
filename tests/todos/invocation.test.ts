import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  TODOS_CONTRACT_DIGEST,
  TODOS_OPERATION_MANIFEST_DIGEST,
  TodosTransferBundleSchema,
  TodosOperationInvocationSchema,
  computeTodosTransferBundleChecksum,
  createTodosTransferCheckpoint,
  createTodosTransferImportPreview,
  validateTodosOperationInvocation,
  type TodosTransferBundle,
  type TodosTransferBundleUnsigned,
} from "../../src/todos";
import {
  buildTodosSchemaBundle,
} from "../../src/todos/schema-registry";

const generatedRoot = join(import.meta.dir, "..", "..", "generated", "todos", "v1");

function identity() {
  return JSON.parse(readFileSync(join(generatedRoot, "fixtures", "identity.valid.json"), "utf8"));
}

function taskCreateInvocation() {
  return {
    mode: "local" as const,
    authorityId: "tenant-a",
    contractDigest: TODOS_CONTRACT_DIGEST,
    manifestDigest: TODOS_OPERATION_MANIFEST_DIGEST,
    operationId: "todos.tasks.create",
    identity: identity(),
    request: {
      title: "Bind one invocation",
      description: null,
      priority: "high",
      projectId: null,
      taskListId: null,
      planId: null,
      parentTaskId: null,
      assignedAgentId: null,
      fingerprint: null,
      tags: [],
      acceptanceCriteria: [],
      dueAt: null,
      externalOwnerRefs: [],
    },
  };
}

function transferBundle(): TodosTransferBundle {
  return TodosTransferBundleSchema.parse(JSON.parse(
    readFileSync(join(generatedRoot, "fixtures", "transfer.valid.json"), "utf8"),
  ));
}

function recalculateBundle(bundle: TodosTransferBundle): TodosTransferBundle {
  const { bundleChecksum: _bundleChecksum, ...unsigned } = bundle;
  return {
    ...bundle,
    bundleChecksum: computeTodosTransferBundleChecksum(unsigned as TodosTransferBundleUnsigned),
  };
}

describe("Todos operation invocation", () => {
  test("binds mode, authority, exact digests, manifest operation, identity, and request", () => {
    const invocation = taskCreateInvocation();
    expect(TodosOperationInvocationSchema.safeParse(invocation).success).toBe(true);
    const validated = validateTodosOperationInvocation(invocation);
    expect(validated.success).toBe(true);
    if (validated.success) {
      expect(validated.operation.id).toBe(invocation.operationId);
      expect(validated.invocation.identity.requestId).toBe("request-1");
    }
  });

  test("rejects missing invocation bindings", () => {
    for (const field of [
      "mode",
      "authorityId",
      "contractDigest",
      "manifestDigest",
      "operationId",
      "identity",
      "request",
    ] as const) {
      const invocation = taskCreateInvocation() as Record<string, unknown>;
      delete invocation[field];
      expect(TodosOperationInvocationSchema.safeParse(invocation).success, field).toBe(false);
    }
  });

  test("rejects mismatched authority, mode, digests, operation, identity, and request", () => {
    const base = taskCreateInvocation();
    const invalid = [
      { ...base, authorityId: "tenant-b" },
      { ...base, contractDigest: "0".repeat(64) },
      { ...base, manifestDigest: "1".repeat(64) },
      { ...base, operationId: "todos.tasks.unknown" },
      { ...base, identity: { ...base.identity, scopes: ["todos:projects:read"] } },
      { ...base, request: { ...base.request, title: "" } },
    ];
    for (const invocation of invalid) {
      expect(TodosOperationInvocationSchema.safeParse(invocation).success).toBe(false);
    }

    const localOnlyWithCloudMode = {
      ...base,
      mode: "cloud",
      operationId: "todos.server.start",
      identity: {
        ...base.identity,
        audience: "tenant_admin",
        roles: ["tenant_admin"],
      },
      request: {
        interface: "loopback",
        port: 4317,
        expectedState: "stopped",
      },
    };
    expect(TodosOperationInvocationSchema.safeParse(localOnlyWithCloudMode).success).toBe(false);
  });

  test("derives required idempotency from the manifest and identity context", () => {
    const requiredWithoutKey = taskCreateInvocation();
    requiredWithoutKey.identity.idempotencyKey = null;
    expect(TodosOperationInvocationSchema.safeParse(requiredWithoutKey).success).toBe(false);

    const readWithoutKey = {
      ...taskCreateInvocation(),
      operationId: "todos.tasks.get",
      identity: {
        ...identity(),
        idempotencyKey: null,
        scopes: ["todos:tasks:read"],
      },
      request: { ref: "task-1" },
    };
    expect(TodosOperationInvocationSchema.safeParse(readWithoutKey).success).toBe(true);

    const schemas = buildTodosSchemaBundle().schemas;
    for (const [schemaId, schema] of Object.entries(schemas)) {
      if (!schemaId.startsWith("hasna.todos.request.")) continue;
      const properties = (schema as { properties?: Record<string, unknown> }).properties ?? {};
      expect(properties).not.toHaveProperty("idempotencyKey");
    }
  });

  test("binds transfer bundles, targets, plans, and checkpoint idempotency to the invocation", () => {
    const bundle = transferBundle();
    const targetAuthorityId = "tenant-a";
    const preview = createTodosTransferImportPreview(bundle, targetAuthorityId);
    const base = {
      ...taskCreateInvocation(),
      operationId: "todos.transfer.import_execute",
      identity: {
        ...identity(),
        scopes: ["todos:transfer:write"],
      },
      request: {
        bundle,
        targetAuthorityId,
        importPlanId: preview.importPlanId,
        importPlanDigest: preview.importPlanDigest,
        checkpoint: null,
      },
    };
    expect(TodosOperationInvocationSchema.safeParse(base).success).toBe(true);

    const wrongContractBundle = structuredClone(bundle);
    wrongContractBundle.contractDigest = "0".repeat(64);
    expect(TodosOperationInvocationSchema.safeParse({
      ...base,
      request: {
        ...base.request,
        bundle: recalculateBundle(wrongContractBundle),
      },
    }).success).toBe(false);
    for (const [operationId, scopes, request] of [
      [
        "todos.transfer.validate",
        ["todos:transfer:read"],
        { bundle: recalculateBundle(wrongContractBundle), dryRun: true },
      ],
      [
        "todos.transfer.import_preview",
        ["todos:transfer:write"],
        {
          bundle: recalculateBundle(wrongContractBundle),
          targetAuthorityId,
          dryRun: true,
        },
      ],
    ] as const) {
      expect(TodosOperationInvocationSchema.safeParse({
        ...base,
        operationId,
        identity: { ...base.identity, scopes },
        request,
      }).success, operationId).toBe(false);
    }

    expect(TodosOperationInvocationSchema.safeParse({
      ...base,
      request: {
        ...base.request,
        targetAuthorityId: "tenant-b",
      },
    }).success).toBe(false);
    expect(TodosOperationInvocationSchema.safeParse({
      ...base,
      request: {
        ...base.request,
        importPlanId: "import-plan:substituted",
      },
    }).success).toBe(false);

    const checkpoint = createTodosTransferCheckpoint({
      sourceAuthorityId: bundle.source.authorityId,
      bundleId: bundle.bundleId,
      bundleChecksum: bundle.bundleChecksum,
      importPlanId: preview.importPlanId,
      importPlanDigest: preview.importPlanDigest,
      contractDigest: bundle.contractDigest,
      manifestDigest: bundle.manifestDigest,
      targetAuthorityId,
      idempotencyKey: "different-request-key",
      sequence: 0,
      completedSections: [],
      nextSection: "projects",
      state: "pending",
    });
    expect(TodosOperationInvocationSchema.safeParse({
      ...base,
      request: {
        ...base.request,
        checkpoint,
      },
    }).success).toBe(false);
  });
});
