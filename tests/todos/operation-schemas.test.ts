import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  TODOS_COMMON_SCHEMA_IDS,
  TODOS_COMMON_SCHEMAS,
  TODOS_REQUEST_SCHEMA_IDS,
  TODOS_REQUEST_SCHEMAS,
  TODOS_RESPONSE_SCHEMA_IDS,
  TODOS_RESPONSE_SCHEMAS,
} from "../../src/todos/operation-schemas";
import {
  TODOS_TRANSFER_SECTION_NAMES,
  computeTodosImportPlanId,
  createTodosTransferCheckpoint,
} from "../../src/todos/transfer-schema";

const generatedRoot = join(import.meta.dir, "..", "..", "generated", "todos", "v1");

function listRequest(limit: number) {
  return {
    cursor: null,
    limit,
    projectId: null,
    taskListId: null,
    planId: null,
    agentId: null,
    status: null,
    changedAfter: null,
  };
}

function transferExecutionRequest() {
  const bundle = JSON.parse(
    readFileSync(join(generatedRoot, "fixtures", "transfer.valid.json"), "utf8"),
  );
  const targetAuthorityId = "tenant-a-cloud";
  const importPlanId = computeTodosImportPlanId({
    sourceAuthorityId: bundle.source.authorityId,
    targetAuthorityId,
    bundleId: bundle.bundleId,
    bundleChecksum: bundle.bundleChecksum,
    contractDigest: bundle.contractDigest,
    manifestDigest: bundle.manifestDigest,
  });
  return {
    bundle,
    targetAuthorityId,
    importPlanId,
    importPlanDigest: "a".repeat(64),
    checkpoint: null,
  };
}

describe("Todos operation schema registries", () => {
  test("maps every exported id exactly once and freezes each registry", () => {
    for (const [idValues, schemas] of [
      [Object.values(TODOS_COMMON_SCHEMA_IDS), TODOS_COMMON_SCHEMAS],
      [Object.values(TODOS_REQUEST_SCHEMA_IDS), TODOS_REQUEST_SCHEMAS],
      [Object.values(TODOS_RESPONSE_SCHEMA_IDS), TODOS_RESPONSE_SCHEMAS],
    ] as const) {
      expect(new Set(idValues).size).toBe(idValues.length);
      expect(Object.keys(schemas).sort()).toEqual([...idValues].sort());
      expect(Object.isFrozen(schemas)).toBe(true);
      for (const schemaId of idValues) {
        const schema = (schemas as Record<
          string,
          { safeParse(input: unknown): { success: boolean } }
        >)[schemaId]!;
        expect(schema.safeParse(undefined).success, schemaId).toBe(false);
      }
    }
  });

  test("keeps the empty request strict and enforces list and bulk boundaries", () => {
    const empty = TODOS_REQUEST_SCHEMAS[TODOS_REQUEST_SCHEMA_IDS.empty];
    expect(empty.safeParse({}).success).toBe(true);
    expect(empty.safeParse({ unexpected: true }).success).toBe(false);

    const list = TODOS_REQUEST_SCHEMAS[TODOS_REQUEST_SCHEMA_IDS.list];
    expect(list.safeParse(listRequest(1)).success).toBe(true);
    expect(list.safeParse(listRequest(500)).success).toBe(true);
    expect(list.safeParse(listRequest(0)).success).toBe(false);
    expect(list.safeParse(listRequest(501)).success).toBe(false);

    const existsMany = TODOS_REQUEST_SCHEMAS[TODOS_REQUEST_SCHEMA_IDS.existsMany];
    expect(existsMany.safeParse({ refs: ["task-1"] }).success).toBe(true);
    expect(existsMany.safeParse({ refs: [] }).success).toBe(false);
    expect(existsMany.safeParse({ refs: Array.from({ length: 10_001 }, (_, index) => `task-${index}`) }).success)
      .toBe(false);
  });

  test("requires a real task update and a positive expected version", () => {
    const schema = TODOS_REQUEST_SCHEMAS[TODOS_REQUEST_SCHEMA_IDS.taskUpdate];
    expect(schema.safeParse({
      ref: "task-1",
      expectedVersion: 1,
      changes: { title: "Updated title" },
    }).success).toBe(true);
    expect(schema.safeParse({ ref: "task-1", expectedVersion: 1, changes: {} }).success)
      .toBe(false);
    expect(schema.safeParse({
      ref: "task-1",
      expectedVersion: 0,
      changes: { title: "Updated title" },
    }).success).toBe(false);
  });

  test("enforces server port boundaries and the stopped-state precondition", () => {
    const schema = TODOS_REQUEST_SCHEMAS[TODOS_REQUEST_SCHEMA_IDS.serverStart];
    const request = { interface: "loopback", port: 1024, expectedState: "stopped" };
    expect(schema.safeParse(request).success).toBe(true);
    expect(schema.safeParse({ ...request, port: 65_535 }).success).toBe(true);
    expect(schema.safeParse({ ...request, port: 1023 }).success).toBe(false);
    expect(schema.safeParse({ ...request, port: 65_536 }).success).toBe(false);
    expect(schema.safeParse({ ...request, expectedState: "started" }).success).toBe(false);
  });

  test("binds transfer execution to its bundle, target, plan, and checkpoint", () => {
    const schema = TODOS_REQUEST_SCHEMAS[TODOS_REQUEST_SCHEMA_IDS.transferImportExecute];
    const request = transferExecutionRequest();
    expect(schema.safeParse(request).success).toBe(true);
    expect(schema.safeParse({ ...request, importPlanId: "import-plan:substituted" }).success)
      .toBe(false);

    const mismatchedTargetAuthorityId = "tenant-b-cloud";
    const checkpoint = createTodosTransferCheckpoint({
      sourceAuthorityId: request.bundle.source.authorityId,
      bundleId: request.bundle.bundleId,
      bundleChecksum: request.bundle.bundleChecksum,
      importPlanId: computeTodosImportPlanId({
        sourceAuthorityId: request.bundle.source.authorityId,
        targetAuthorityId: mismatchedTargetAuthorityId,
        bundleId: request.bundle.bundleId,
        bundleChecksum: request.bundle.bundleChecksum,
        contractDigest: request.bundle.contractDigest,
        manifestDigest: request.bundle.manifestDigest,
      }),
      importPlanDigest: request.importPlanDigest,
      contractDigest: request.bundle.contractDigest,
      manifestDigest: request.bundle.manifestDigest,
      targetAuthorityId: mismatchedTargetAuthorityId,
      idempotencyKey: "import-key-1",
      sequence: 0,
      completedSections: [],
      nextSection: TODOS_TRANSFER_SECTION_NAMES[0]!,
      state: "pending",
    });
    expect(schema.safeParse({ ...request, checkpoint }).success).toBe(false);
  });

  test("accepts success and refusal responses while rejecting malformed envelopes", () => {
    const count = TODOS_RESPONSE_SCHEMAS[TODOS_RESPONSE_SCHEMA_IDS.count];
    expect(count.safeParse({
      ok: true,
      data: { count: 0 },
      requestId: "request-1",
    }).success).toBe(true);
    expect(count.safeParse({
      ok: false,
      error: {
        code: "TODOS_ACCESS_DENIED",
        message: "Access denied",
        retryable: false,
        details: [],
      },
      requestId: "request-1",
    }).success).toBe(true);
    expect(count.safeParse({ ok: true, data: { count: -1 }, requestId: "request-1" }).success)
      .toBe(false);
    expect(count.safeParse({ ok: false, requestId: "request-1" }).success).toBe(false);
  });

  test("validates common errors and mutation receipts", () => {
    const error = TODOS_COMMON_SCHEMAS[TODOS_COMMON_SCHEMA_IDS.error];
    expect(error.safeParse({
      code: "TODOS_INVALID_INPUT",
      message: "Invalid request",
      retryable: false,
      details: [],
    }).success).toBe(true);
    expect(error.safeParse({
      code: "UNKNOWN",
      message: "Invalid request",
      retryable: false,
      details: [],
    }).success).toBe(false);

    const receipt = TODOS_COMMON_SCHEMAS[TODOS_COMMON_SCHEMA_IDS.mutationReceipt];
    const valid = {
      operationId: "todos.tasks.update",
      resourceId: "task-1",
      changed: true,
      replayed: false,
      version: 2,
    };
    expect(receipt.safeParse(valid).success).toBe(true);
    expect(receipt.safeParse({ ...valid, version: 0 }).success).toBe(false);
  });
});
