import { describe, expect, test } from "bun:test";
import * as todos from "../../src/todos/index";

const historicalContractDigest = "0".repeat(64);
const historicalManifestDigest = "3".repeat(64);
const bundleChecksum = "1".repeat(64);
const importPlanDigest = "2".repeat(64);
const timestamp = "2026-07-24T02:00:00.000Z";

function historicalBinding(
  digests: {
    contractDigest: string;
    manifestDigest: string;
  } = {
    contractDigest: historicalContractDigest,
    manifestDigest: todos.TODOS_OPERATION_MANIFEST_DIGEST,
  },
) {
  const identity = {
    sourceAuthorityId: "tenant-a",
    targetAuthorityId: "tenant-a-cloud",
    bundleId: "bundle-historical",
    bundleChecksum,
    ...digests,
  };
  return {
    ...identity,
    importPlanId: todos.computeTodosImportPlanId(identity),
    importPlanDigest,
    idempotencyKey: "historical-key",
  };
}

function structuralCheckpoint(
  state: "pending" | "interrupted" | "committed",
  binding = historicalBinding(),
) {
  const terminal = state === "committed";
  const completedSections = terminal
    ? [...todos.TODOS_TRANSFER_SECTION_NAMES]
    : [];
  const unsigned = {
    schema: todos.TODOS_TRANSFER_SCHEMA_IDS.checkpoint,
    ...binding,
    sequence: completedSections.length,
    completedSections,
    nextSection: terminal ? null : "projects" as const,
    state,
  };
  return {
    ...unsigned,
    digest: todos.sha256TodosValue(unsigned),
  };
}

function structuralReceipt(binding = historicalBinding()) {
  const checkpoint = structuralCheckpoint("committed", binding);
  const unsigned = {
    schema: todos.TODOS_TRANSFER_SCHEMA_IDS.migrationReceipt,
    id: "receipt-historical",
    receiptSequence: 1,
    previousReceiptDigest: null,
    ...binding,
    status: "committed" as const,
    importedCounts: Object.fromEntries(
      todos.TODOS_TRANSFER_SECTION_NAMES.map((name) => [name, 0]),
    ),
    checkpoint,
    committedAt: timestamp,
  };
  return {
    ...unsigned,
    receiptDigest: todos.sha256TodosValue(unsigned),
  };
}

function canonicalEmptyBundle() {
  return todos.createTodosTransferBundle({
    bundleId: "bundle-public-operation-map",
    createdAt: timestamp,
    source: {
      authorityId: "tenant-a",
      mode: "local",
    },
    records: Object.fromEntries(
      todos.TODOS_TRANSFER_SECTION_NAMES.map((name) => [name, []]),
    ) as unknown as Parameters<
      typeof todos.createTodosTransferBundle
    >[0]["records"],
  });
}

function bundleWithHistoricalDigest(
  field: "contractDigest" | "manifestDigest",
) {
  const canonical = canonicalEmptyBundle();
  const changed = {
    ...canonical,
    [field]: field === "contractDigest"
      ? historicalContractDigest
      : historicalManifestDigest,
  };
  const {
    bundleChecksum: _bundleChecksum,
    ...unsigned
  } = changed;
  return {
    ...changed,
    bundleChecksum: todos.computeTodosTransferBundleChecksum(unsigned),
  };
}

function transferImportExecuteRequest(
  bundle: ReturnType<typeof canonicalEmptyBundle>,
) {
  const targetAuthorityId = "tenant-a-cloud";
  const importPlanId = todos.computeTodosImportPlanId({
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
    importPlanDigest,
    checkpoint: structuralCheckpoint("pending", {
      sourceAuthorityId: bundle.source.authorityId,
      targetAuthorityId,
      bundleId: bundle.bundleId,
      bundleChecksum: bundle.bundleChecksum,
      contractDigest: bundle.contractDigest,
      manifestDigest: bundle.manifestDigest,
      importPlanId,
      importPlanDigest,
      idempotencyKey: "public-operation-map-key",
    }),
  };
}

describe("Todos public export boundary", () => {
  test("does not expose structural foundation or registry parsing", () => {
    for (const structuralName of [
      "TODOS_SCHEMA_FOUNDATION_REGISTRY",
      "TODOS_SCHEMA_FOUNDATION",
      "TODOS_SCHEMA_BUNDLE_DIGEST",
      "buildTodosJsonSchemas",
      "TODOS_SCHEMA_REGISTRY",
      "getTodosSchema",
      "parseTodosSchema",
      "buildTodosSchemaBundle",
    ]) {
      expect(structuralName in todos, structuralName).toBe(false);
    }
  });

  test("keeps every public checkpoint and receipt boundary canonical", () => {
    const checkpoint = structuralCheckpoint("pending");
    const terminal = structuralCheckpoint("committed");
    const receipt = structuralReceipt();

    expect(todos.TodosTransferCheckpointSchema.safeParse(checkpoint).success)
      .toBe(false);
    expect(
      todos.TODOS_TRANSFER_SCHEMAS[
        todos.TODOS_TRANSFER_SCHEMA_IDS.checkpoint
      ].safeParse(checkpoint).success,
    ).toBe(false);
    expect(() => todos.createTodosTransferCheckpoint({
      ...historicalBinding(),
      sequence: 0,
      completedSections: [],
      nextSection: "projects",
      state: "pending",
    })).toThrow();
    expect(
      todos.validateTodosTransferCheckpointTransition(checkpoint, terminal),
    ).toBe(false);

    expect(todos.TodosMigrationReceiptSchema.safeParse(receipt).success)
      .toBe(false);
    expect(
      todos.TODOS_TRANSFER_SCHEMAS[
        todos.TODOS_TRANSFER_SCHEMA_IDS.migrationReceipt
      ].safeParse(receipt).success,
    ).toBe(false);
    const {
      schema: _schema,
      status: _status,
      receiptDigest: _receiptDigest,
      ...receiptInput
    } = receipt;
    expect(() => todos.createTodosMigrationReceipt(receiptInput)).toThrow();
    expect(todos.validateTodosMigrationReceiptChain([receipt])).toMatchObject({
      success: false,
      action: "conflict",
    });
    expect(todos.TodosTransferExecutionContextSchema.safeParse({
      state: "committed",
      receipt,
    }).success).toBe(false);
  });

  test("keeps every public operation map checkpoint and receipt boundary canonical", () => {
    const boundarySchemaIds = [
      ...todos.TODOS_OPERATION_MANIFEST.operations.flatMap((operation) => {
        if (operation.resource === "transfer" && operation.action === "import_execute") {
          return [operation.requestSchemaId, operation.responseSchemaId];
        }
        if (operation.resource === "migration_receipts") {
          return [operation.responseSchemaId];
        }
        return [];
      }),
    ];
    expect([...new Set(boundarySchemaIds)].sort()).toEqual([
      todos.TODOS_REQUEST_SCHEMA_IDS.transferImportExecute,
      todos.TODOS_RESPONSE_SCHEMA_IDS.migrationReceipt,
      todos.TODOS_RESPONSE_SCHEMA_IDS.migrationReceiptPage,
    ].sort());

    const requestSchema = todos.TODOS_REQUEST_SCHEMAS[
      todos.TODOS_REQUEST_SCHEMA_IDS.transferImportExecute
    ];
    const receiptSchema = todos.TODOS_RESPONSE_SCHEMAS[
      todos.TODOS_RESPONSE_SCHEMA_IDS.migrationReceipt
    ];
    const receiptPageSchema = todos.TODOS_RESPONSE_SCHEMAS[
      todos.TODOS_RESPONSE_SCHEMA_IDS.migrationReceiptPage
    ];

    expect(
      requestSchema.safeParse(
        transferImportExecuteRequest(canonicalEmptyBundle()),
      ).success,
    ).toBe(true);
    const canonicalReceipt = structuralReceipt(historicalBinding({
      contractDigest: todos.TODOS_CONTRACT_DIGEST,
      manifestDigest: todos.TODOS_OPERATION_MANIFEST_DIGEST,
    }));
    expect(receiptSchema.safeParse({
      ok: true,
      data: canonicalReceipt,
      requestId: "request-map-1",
    }).success).toBe(true);
    expect(receiptPageSchema.safeParse({
      ok: true,
      data: {
        items: [canonicalReceipt],
        count: 1,
        nextCursor: null,
      },
      requestId: "request-map-1",
    }).success).toBe(true);

    for (const field of ["contractDigest", "manifestDigest"] as const) {
      const bundle = bundleWithHistoricalDigest(field);
      expect(
        requestSchema.safeParse(transferImportExecuteRequest(bundle)).success,
        `transferImportExecute:${field}`,
      ).toBe(false);

      const receipt = structuralReceipt(historicalBinding({
        contractDigest: field === "contractDigest"
          ? historicalContractDigest
          : todos.TODOS_CONTRACT_DIGEST,
        manifestDigest: field === "manifestDigest"
          ? historicalManifestDigest
          : todos.TODOS_OPERATION_MANIFEST_DIGEST,
      }));
      expect(receiptSchema.safeParse({
        ok: true,
        data: receipt,
        requestId: "request-map-1",
      }).success, `migrationReceipt:${field}`).toBe(false);
      expect(receiptPageSchema.safeParse({
        ok: true,
        data: {
          items: [receipt],
          count: 1,
          nextCursor: null,
        },
        requestId: "request-map-1",
      }).success, `migrationReceiptPage:${field}`).toBe(false);
    }
  });
});
