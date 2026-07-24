import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as todos from "../../src/todos";
import {
  TODOS_CONTRACT_DIGEST,
  TODOS_OPERATION_MANIFEST_DIGEST,
  TODOS_TRANSFER_CLASSIFICATION,
  TODOS_TRANSFER_SECTION_NAMES,
  TodosDeletionRecordSchema,
  TodosMigrationReceiptSchema,
  TodosPortableRunArtifactSchema,
  TodosPortableRunCommandSchema,
  TodosTransferBundleSchema,
  TodosTransferCheckpointSchema,
  TodosTransferExecutionContextSchema,
  computeTodosImportPlanId,
  computeTodosTransferBundleChecksum,
  createTodosMigrationReceipt,
  createTodosTransferBundle,
  createTodosTransferCheckpoint,
  createTodosTransferImportPreview,
  evaluateTodosImportExecution,
  sha256TodosText,
  sha256TodosValue,
  validateTodosMigrationReceiptChain,
  validateTodosTransferBundle,
  validateTodosTransferCheckpointTransition,
  type TodosMigrationReceipt,
  type TodosTransferBundle,
  type TodosTransferBundleUnsigned,
} from "../../src/todos";

const generatedRoot = join(import.meta.dir, "..", "..", "generated", "todos", "v1", "fixtures");

function loadBundle(name = "transfer.valid.json"): TodosTransferBundle {
  return TodosTransferBundleSchema.parse(JSON.parse(readFileSync(join(generatedRoot, name), "utf8")));
}

function recalculateBundle(bundle: TodosTransferBundle): TodosTransferBundle {
  const { bundleChecksum: _bundleChecksum, ...unsigned } = bundle;
  return {
    ...bundle,
    bundleChecksum: computeTodosTransferBundleChecksum(unsigned as TodosTransferBundleUnsigned),
  };
}

function importContext(
  bundle: TodosTransferBundle,
  idempotencyKey = "import-key-1",
) {
  const targetAuthorityId = "tenant-a-cloud";
  const preview = createTodosTransferImportPreview(bundle, targetAuthorityId);
  return {
    sourceAuthorityId: preview.sourceAuthorityId,
    bundleId: bundle.bundleId,
    bundleChecksum: bundle.bundleChecksum,
    importPlanId: preview.importPlanId,
    importPlanDigest: preview.importPlanDigest,
    contractDigest: bundle.contractDigest,
    manifestDigest: bundle.manifestDigest,
    targetAuthorityId,
    idempotencyKey,
  };
}

function committedCheckpoint(
  bundle: TodosTransferBundle,
  idempotencyKey = "import-key-1",
) {
  const context = importContext(bundle, idempotencyKey);
  return createTodosTransferCheckpoint({
    ...context,
    sequence: TODOS_TRANSFER_SECTION_NAMES.length,
    completedSections: [...TODOS_TRANSFER_SECTION_NAMES],
    nextSection: null,
    state: "committed",
  });
}

function migrationReceipt(
  bundle: TodosTransferBundle,
  overrides: Partial<Parameters<typeof createTodosMigrationReceipt>[0]> = {},
): TodosMigrationReceipt {
  const checkpoint = committedCheckpoint(
    bundle,
    overrides.idempotencyKey ?? "import-key-1",
  );
  return createTodosMigrationReceipt({
    id: "receipt-1",
    receiptSequence: 1,
    previousReceiptDigest: null,
    sourceAuthorityId: bundle.source.authorityId,
    targetAuthorityId: checkpoint.targetAuthorityId,
    bundleId: bundle.bundleId,
    bundleChecksum: bundle.bundleChecksum,
    importPlanId: checkpoint.importPlanId,
    importPlanDigest: checkpoint.importPlanDigest,
    contractDigest: bundle.contractDigest,
    manifestDigest: bundle.manifestDigest,
    idempotencyKey: checkpoint.idempotencyKey,
    importedCounts: Object.fromEntries(
      Object.entries(bundle.sections).map(([name, section]) => [name, section.count]),
    ),
    checkpoint,
    committedAt: "2026-07-24T00:05:00.000Z",
    ...overrides,
  });
}

describe("Todos transfer bundle", () => {
  test("validates counts, digests, every foreign-key closure, content refs, and checksum", () => {
    const bundle = loadBundle();
    const validation = validateTodosTransferBundle(bundle);
    expect(validation.valid).toBe(true);
    expect(validation.issues).toEqual([]);
    expect(bundle.sections.tasks.count).toBe(2);
    expect(bundle.dependencyClosure).toEqual([
      { owner: "tenant-a", taskId: "task-1", dependencyTaskIds: [] },
      { owner: "tenant-a", taskId: "task-2", dependencyTaskIds: ["task-1"] },
    ]);
    expect(bundle.referenceClosure).toContainEqual({
      source: { owner: "tenant-a", section: "tasks", id: "task-1" },
      references: [{ owner: "tenant-a", section: "projects", id: "project-1" }],
    });
    expect(bundle.referenceClosure).toContainEqual({
      source: { owner: "tenant-a", section: "task_files", id: "task-file-1" },
      references: [
        { owner: "tenant-a", section: "projects", id: "project-1" },
        { owner: "tenant-a", section: "tasks", id: "task-1" },
      ],
    });
    expect(bundle.attachmentContentReferences).toHaveLength(1);
    expect(bundle.attachmentContentReferences[0]?.source.section).toBe("task_files");
  });

  test("rejects internally rehashed foreign contract and manifest digests", () => {
    const bundle = structuredClone(loadBundle());
    bundle.contractDigest = sha256TodosText("foreign-contract");
    bundle.manifestDigest = sha256TodosText("foreign-manifest");
    const rehashed = recalculateBundle(bundle);
    const validation = validateTodosTransferBundle(rehashed);
    expect(validation.valid).toBe(false);
    expect(validation.issues.filter((issue) => issue.code === "canonical_digest_mismatch"))
      .toHaveLength(2);
    expect(createTodosTransferImportPreview(rehashed, "tenant-a-cloud").valid).toBe(false);
  });

  test("rejects mixed source owners at section, record, and nested-ref depth", () => {
    const sectionOwner = structuredClone(loadBundle());
    sectionOwner.sections.projects.owner = "tenant-b";
    expect(validateTodosTransferBundle(recalculateBundle(sectionOwner)).valid).toBe(false);

    const recordOwner = structuredClone(loadBundle());
    recordOwner.sections.tasks.records[0]!.owner = "tenant-b";
    recordOwner.sections.tasks.digest = sha256TodosValue(recordOwner.sections.tasks.records);
    expect(validateTodosTransferBundle(recalculateBundle(recordOwner)).valid).toBe(false);

    const nestedOwner = structuredClone(loadBundle());
    nestedOwner.sections.projects.records[0]!.repositoryRef!.owner = "tenant-b";
    nestedOwner.sections.projects.digest = sha256TodosValue(nestedOwner.sections.projects.records);
    expect(validateTodosTransferBundle(recalculateBundle(nestedOwner)).valid).toBe(false);
  });

  test("uses content-addressed command metadata and rejects raw command or path injection", () => {
    const bundle = loadBundle();
    expect(bundle.sections.task_files.records[0]).not.toHaveProperty("relativePath");
    expect(JSON.stringify(bundle)).not.toContain("artifacts/contract.json");

    const command = {
      id: "command-1",
      owner: "tenant-a",
      version: 1,
      createdAt: bundle.createdAt,
      updatedAt: bundle.createdAt,
      runId: "run-1",
      sequence: 0,
      commandDigest: sha256TodosText("redacted-command"),
      argumentsDigest: sha256TodosText("redacted-arguments"),
      exitCode: 0,
      durationMs: 1,
      outputRefs: [],
      completedAt: bundle.createdAt,
    };
    expect(TodosPortableRunCommandSchema.safeParse(command).success).toBe(true);
    for (const injection of [
      { command: "rm -rf /tmp/example" },
      { arguments: ["--secret"] },
      { relativePath: "private/output.txt" },
      { absolutePath: "/private/output.txt" },
    ]) {
      expect(TodosPortableRunCommandSchema.safeParse({ ...command, ...injection }).success)
        .toBe(false);
    }

    const artifact = {
      id: "artifact-1",
      owner: "tenant-a",
      version: 1,
      createdAt: bundle.createdAt,
      updatedAt: bundle.createdAt,
      runId: "run-1",
      logicalName: "report.json",
      kind: "report" as const,
      contentRef: {
        algorithm: "sha256" as const,
        digest: sha256TodosText("redacted-report"),
        mediaType: "application/json",
        byteLength: 17,
      },
      verified: true,
      verificationEvidenceId: null,
    };
    expect(TodosPortableRunArtifactSchema.safeParse(artifact).success).toBe(true);
    expect(
      TodosPortableRunArtifactSchema.safeParse({
        ...artifact,
        logicalName: "private/report.json",
      }).success,
    ).toBe(false);
    expect(
      TodosPortableRunArtifactSchema.safeParse({
        ...artifact,
        relativePath: "private/report.json",
      }).success,
    ).toBe(false);

    const pathInjection = structuredClone(bundle) as unknown as Record<string, any>;
    pathInjection.sections.task_files.records[0].relativePath = "private/output.txt";
    pathInjection.sections.task_files.digest = sha256TodosValue(
      pathInjection.sections.task_files.records,
    );
    const { bundleChecksum: _checksum, ...unsigned } = pathInjection;
    pathInjection.bundleChecksum = computeTodosTransferBundleChecksum(
      unsigned as TodosTransferBundleUnsigned,
    );
    expect(validateTodosTransferBundle(pathInjection).valid).toBe(false);
  });

  test("detects count, section digest, bundle checksum, and both closure drifts independently", () => {
    const countDrift = structuredClone(loadBundle());
    countDrift.sections.tasks.count += 1;
    countDrift.bundleChecksum = computeTodosTransferBundleChecksum(
      (({ bundleChecksum: _checksum, ...unsigned }) => unsigned)(countDrift),
    );
    expect(validateTodosTransferBundle(countDrift).issues.some((issue) => issue.code === "count_mismatch")).toBe(true);

    const digestDrift = structuredClone(loadBundle());
    digestDrift.sections.tasks.digest = sha256TodosText("wrong-section");
    digestDrift.bundleChecksum = computeTodosTransferBundleChecksum(
      (({ bundleChecksum: _checksum, ...unsigned }) => unsigned)(digestDrift),
    );
    expect(validateTodosTransferBundle(digestDrift).issues.some((issue) => issue.code === "section_digest_mismatch")).toBe(true);

    const checksumDrift = structuredClone(loadBundle());
    checksumDrift.bundleChecksum = sha256TodosText("wrong-bundle");
    expect(validateTodosTransferBundle(checksumDrift).issues.some((issue) => issue.code === "bundle_checksum_mismatch")).toBe(true);

    const closureDrift = structuredClone(loadBundle());
    closureDrift.dependencyClosure = [];
    const closureRecalculated = recalculateBundle(closureDrift);
    expect(validateTodosTransferBundle(closureRecalculated).issues.some((issue) => issue.code === "closure_mismatch")).toBe(true);

    const referenceClosureDrift = structuredClone(loadBundle());
    referenceClosureDrift.referenceClosure = [];
    const referenceClosureRecalculated = recalculateBundle(referenceClosureDrift);
    expect(
      validateTodosTransferBundle(referenceClosureRecalculated).issues
        .some((issue) => issue.code === "reference_closure_mismatch"),
    ).toBe(true);
  });

  test("detects missing references after hashes are made internally consistent", () => {
    const bundle = structuredClone(loadBundle());
    bundle.sections.projects.records = [];
    bundle.sections.projects.count = 0;
    bundle.sections.projects.digest = sha256TodosValue([]);
    const recalculated = recalculateBundle(bundle);
    expect(validateTodosTransferBundle(recalculated).issues.some((issue) => issue.code === "missing_reference")).toBe(true);
  });

  test("rejects duplicate records and excluded or unclassified fields even with repaired hashes", () => {
    const duplicate = structuredClone(loadBundle());
    duplicate.sections.tasks.records.push(structuredClone(duplicate.sections.tasks.records[0]!));
    duplicate.sections.tasks.count = duplicate.sections.tasks.records.length;
    duplicate.sections.tasks.digest = sha256TodosValue(duplicate.sections.tasks.records);
    duplicate.dependencyClosure.push(structuredClone(duplicate.dependencyClosure[0]!));
    const duplicateRecalculated = recalculateBundle(duplicate);
    expect(
      validateTodosTransferBundle(duplicateRecalculated).issues
        .some((issue) => issue.code === "duplicate_record"),
    ).toBe(true);

    const excluded = structuredClone(loadBundle()) as TodosTransferBundle & {
      sections: TodosTransferBundle["sections"] & {
        tasks: TodosTransferBundle["sections"]["tasks"] & {
          records: Array<TodosTransferBundle["sections"]["tasks"]["records"][number] & {
            authenticationToken?: string;
          }>;
        };
      };
    };
    excluded.sections.tasks.records[0]!.authenticationToken = "excluded";
    excluded.sections.tasks.digest = sha256TodosValue(excluded.sections.tasks.records);
    const excludedRecalculated = recalculateBundle(excluded);
    expect(
      validateTodosTransferBundle(excludedRecalculated).issues
        .some((issue) => issue.code === "invalid_bundle"),
    ).toBe(true);
  });

  test("is deterministic regardless of input record order", () => {
    const bundle = loadBundle();
    const records = Object.fromEntries(
      Object.entries(bundle.sections).map(([name, section]) => [name, [...section.records].reverse()]),
    ) as Parameters<typeof createTodosTransferBundle>[0]["records"];
    const regenerated = createTodosTransferBundle({
      bundleId: bundle.bundleId,
      createdAt: bundle.createdAt,
      source: bundle.source,
      records,
    });
    expect(regenerated).toEqual(bundle);
  });

  test("keeps deletion history append-only and redacted", () => {
    const record = loadBundle().sections.deletion_records.records[0]!;
    expect(record.redaction).toBe("full");
    expect(TodosDeletionRecordSchema.safeParse({ ...record, rawPayload: { title: "deleted" } }).success).toBe(false);
    expect(TodosDeletionRecordSchema.safeParse({ ...record, redaction: "none" }).success).toBe(false);
  });

  test("keeps agent and external-owner identities reference-only", () => {
    expect(TODOS_TRANSFER_CLASSIFICATION.referenceOnly).toEqual([
      "agent_ids",
      "external_owner_ids",
      "owner_qualified_refs",
    ]);
    expect(TODOS_TRANSFER_CLASSIFICATION.portableSections).not.toContain("agents");
    expect(TODOS_TRANSFER_CLASSIFICATION.excludedCategories).toContain("authentication_tokens");
    expect(TODOS_TRANSFER_CLASSIFICATION.excludedCategories).toContain("worker_state");
    expect(TODOS_TRANSFER_CLASSIFICATION.excludedCategories).toContain("provider_internals");
  });
});

describe("Todos transfer replay and receipt", () => {
  test("validates bound monotonic checkpoints and rejects regression or substitution", () => {
    const bundle = loadBundle();
    const context = importContext(bundle);
    const first = createTodosTransferCheckpoint({
      ...context,
      sequence: 0,
      completedSections: [],
      nextSection: "projects",
      state: "pending",
    });
    const second = createTodosTransferCheckpoint({
      ...context,
      sequence: 1,
      completedSections: ["projects"],
      nextSection: "task_lists",
      state: "interrupted",
    });
    expect(validateTodosTransferCheckpointTransition(first, second)).toBe(true);
    expect(validateTodosTransferCheckpointTransition(second, first)).toBe(false);

    const substitutedContext = {
      ...context,
      targetAuthorityId: "tenant-b-cloud",
    };
    const substituted = createTodosTransferCheckpoint({
      ...substitutedContext,
      importPlanId: computeTodosImportPlanId(substitutedContext),
      sequence: 1,
      completedSections: ["projects"],
      nextSection: "task_lists",
      state: "interrupted",
    });
    expect(validateTodosTransferCheckpointTransition(first, substituted)).toBe(false);

    const wrongPlan = createTodosTransferCheckpoint({
      ...context,
      importPlanDigest: sha256TodosText("substituted-plan"),
      sequence: 1,
      completedSections: ["projects"],
      nextSection: "task_lists",
      state: "interrupted",
    });
    expect(validateTodosTransferCheckpointTransition(first, wrongPlan)).toBe(false);

    const tampered = {
      ...second,
      sequence: 2,
    };
    expect(TodosTransferCheckpointSchema.safeParse(tampered).success).toBe(false);
  });

  test("binds committed receipts, validates their chain, and detects substitutions", () => {
    const bundle = loadBundle();
    const firstReceipt = migrationReceipt(bundle);
    expect(TodosMigrationReceiptSchema.safeParse(firstReceipt).success).toBe(true);

    const secondCheckpoint = committedCheckpoint(bundle, "import-key-2");
    const secondReceipt = migrationReceipt(bundle, {
      id: "receipt-2",
      receiptSequence: 2,
      previousReceiptDigest: firstReceipt.receiptDigest,
      idempotencyKey: "import-key-2",
      checkpoint: secondCheckpoint,
      importPlanDigest: secondCheckpoint.importPlanDigest,
      committedAt: "2026-07-24T00:06:00.000Z",
    });
    expect(validateTodosMigrationReceiptChain([firstReceipt, secondReceipt])).toEqual({
      success: true,
      action: "valid",
      canonicalReceiptCount: 2,
    });
    expect(validateTodosMigrationReceiptChain([secondReceipt, firstReceipt]).success).toBe(false);
    expect(validateTodosMigrationReceiptChain([firstReceipt, {
      ...secondReceipt,
      previousReceiptDigest: sha256TodosText("substituted-receipt"),
    }]).success).toBe(false);

    const receiptSubstitution = {
      ...firstReceipt,
      bundleId: "bundle-substituted",
    };
    expect(TodosMigrationReceiptSchema.safeParse(receiptSubstitution).success).toBe(false);
  });

  test("binds each receipt-chain idempotency key to one terminal import result", () => {
    const bundle = loadBundle();
    const firstReceipt = migrationReceipt(bundle);
    const preview = createTodosTransferImportPreview(bundle, "tenant-a-cloud");
    expect((preview as Record<string, unknown>).importPlanId).toBeString();

    const differentBundle = recalculateBundle({
      ...structuredClone(bundle),
      bundleId: "bundle-different",
    });
    const differentTupleCheckpoint = committedCheckpoint(
      differentBundle,
      firstReceipt.idempotencyKey,
    );
    const differentTupleReceipt = migrationReceipt(differentBundle, {
      id: "receipt-different-tuple",
      receiptSequence: 2,
      previousReceiptDigest: firstReceipt.receiptDigest,
      idempotencyKey: firstReceipt.idempotencyKey,
      checkpoint: differentTupleCheckpoint,
      importPlanDigest: differentTupleCheckpoint.importPlanDigest,
      committedAt: "2026-07-24T00:06:00.000Z",
    });
    expect(validateTodosMigrationReceiptChain([
      firstReceipt,
      differentTupleReceipt,
    ])).toMatchObject({
      success: false,
      action: "conflict",
    });

    const duplicateCheckpoint = committedCheckpoint(
      bundle,
      firstReceipt.idempotencyKey,
    );
    const duplicateCommit = migrationReceipt(bundle, {
      id: "receipt-duplicate-commit",
      receiptSequence: 2,
      previousReceiptDigest: firstReceipt.receiptDigest,
      idempotencyKey: firstReceipt.idempotencyKey,
      checkpoint: duplicateCheckpoint,
      importPlanDigest: duplicateCheckpoint.importPlanDigest,
      committedAt: "2026-07-24T00:07:00.000Z",
    });
    expect(validateTodosMigrationReceiptChain([
      firstReceipt,
      duplicateCommit,
    ])).toMatchObject({
      success: false,
      action: "conflict",
    });

    expect(validateTodosMigrationReceiptChain([
      firstReceipt,
      structuredClone(firstReceipt),
    ])).toMatchObject({
      success: true,
      action: "replay",
      canonicalReceiptCount: 1,
      receipt: firstReceipt,
    });
  });

  test("rejects historical digests at every public checkpoint and receipt boundary", () => {
    const bundle = loadBundle();
    const canonical = importContext(bundle);
    const wrongDigests = [
      {
        ...canonical,
        contractDigest: sha256TodosText("historical-contract"),
      },
      {
        ...canonical,
        manifestDigest: sha256TodosText("historical-manifest"),
      },
    ].map((context) => ({
      ...context,
      importPlanId: computeTodosImportPlanId(context),
    }));

    const structuralCheckpoint = (
      context: typeof canonical,
      sequence: number,
      completedSections: typeof TODOS_TRANSFER_SECTION_NAMES[number][],
      nextSection: typeof TODOS_TRANSFER_SECTION_NAMES[number] | null,
      state: "pending" | "interrupted" | "committed",
    ) => {
      const unsigned = {
        schema: "hasna.todos.transfer_checkpoint.v1" as const,
        ...context,
        sequence,
        completedSections,
        nextSection,
        state,
      };
      return {
        ...unsigned,
        digest: sha256TodosValue(unsigned),
      };
    };

    for (const wrong of wrongDigests) {
      const first = structuralCheckpoint(wrong, 0, [], "projects", "pending");
      const terminal = structuralCheckpoint(
        wrong,
        TODOS_TRANSFER_SECTION_NAMES.length,
        [...TODOS_TRANSFER_SECTION_NAMES],
        null,
        "committed",
      );
      const terminalInput = {
        id: `receipt-${wrong.contractDigest.slice(0, 8)}-${wrong.manifestDigest.slice(0, 8)}`,
        receiptSequence: 1,
        previousReceiptDigest: null,
        sourceAuthorityId: wrong.sourceAuthorityId,
        targetAuthorityId: wrong.targetAuthorityId,
        bundleId: wrong.bundleId,
        bundleChecksum: wrong.bundleChecksum,
        importPlanId: wrong.importPlanId,
        importPlanDigest: wrong.importPlanDigest,
        contractDigest: wrong.contractDigest,
        manifestDigest: wrong.manifestDigest,
        idempotencyKey: wrong.idempotencyKey,
        importedCounts: Object.fromEntries(
          TODOS_TRANSFER_SECTION_NAMES.map((name) => [name, bundle.sections[name].count]),
        ),
        checkpoint: terminal,
        committedAt: "2026-07-24T00:08:00.000Z",
      };
      const receiptUnsigned = {
        schema: "hasna.todos.migration_receipt.v1" as const,
        ...terminalInput,
        status: "committed" as const,
      };
      const receipt = {
        ...receiptUnsigned,
        receiptDigest: sha256TodosValue(receiptUnsigned),
      };

      expect(TodosTransferCheckpointSchema.safeParse(first).success).toBe(false);
      expect(
        todos.TODOS_TRANSFER_SCHEMAS[
          todos.TODOS_TRANSFER_SCHEMA_IDS.checkpoint
        ].safeParse(first).success,
      ).toBe(false);
      expect(() => createTodosTransferCheckpoint({
        ...wrong,
        sequence: 0,
        completedSections: [],
        nextSection: "projects",
        state: "pending",
      })).toThrow();
      expect(validateTodosTransferCheckpointTransition(first, terminal)).toBe(false);
      expect(TodosMigrationReceiptSchema.safeParse(receipt).success).toBe(false);
      expect(
        todos.TODOS_TRANSFER_SCHEMAS[
          todos.TODOS_TRANSFER_SCHEMA_IDS.migrationReceipt
        ].safeParse(receipt).success,
      ).toBe(false);
      expect(() => createTodosMigrationReceipt(terminalInput)).toThrow();
      expect(validateTodosMigrationReceiptChain([receipt])).toMatchObject({
        success: false,
        action: "conflict",
      });
      expect(TodosTransferExecutionContextSchema.safeParse({
        state: "committed",
        receipt,
      }).success).toBe(false);
      expect(
        todos.TODOS_TRANSFER_SCHEMAS[
          todos.TODOS_TRANSFER_SCHEMA_IDS.executionContext
        ].safeParse({
          state: "committed",
          receipt,
        }).success,
      ).toBe(false);
      const execution = {
        schema: "hasna.todos.transfer_import_execution.v1" as const,
        ...wrong,
        checkpoint: first,
      };
      expect(todos.TodosTransferImportExecutionSchema.safeParse(execution).success)
        .toBe(false);
      expect(
        todos.TODOS_TRANSFER_SCHEMAS[
          todos.TODOS_TRANSFER_SCHEMA_IDS.importExecution
        ].safeParse(execution).success,
      ).toBe(false);
      expect(evaluateTodosImportExecution(execution, { state: "uncommitted" }).action)
        .toBe("reject");
    }

    for (const internalName of [
      "TodosTransferCheckpointStructuralSchema",
      "TodosMigrationReceiptStructuralSchema",
      "createTodosTransferCheckpointIntegrity",
      "createTodosMigrationReceiptIntegrity",
      "validateTodosMigrationReceiptChainIntegrity",
      "validateTodosTransferCheckpointTransitionIntegrity",
    ]) {
      expect(internalName in todos, internalName).toBe(false);
    }
  });

  test("replays only identical committed imports and rejects idempotency substitution", () => {
    const bundle = loadBundle();
    const context = importContext(bundle);
    const receipt = migrationReceipt(bundle);
    const request = {
      schema: "hasna.todos.transfer_import_execution.v1" as const,
      ...context,
      checkpoint: null,
    };
    const committed = { state: "committed" as const, receipt };
    expect(evaluateTodosImportExecution(request, committed)).toEqual({ action: "replay", receipt });
    expect(evaluateTodosImportExecution({
      ...request,
      idempotencyKey: "import-key-new",
    }, committed)).toEqual({ action: "commit" });

    const conflictRequest = {
      ...request,
      bundleChecksum: sha256TodosText("different-bundle"),
    };
    const conflict = evaluateTodosImportExecution({
      ...conflictRequest,
      importPlanId: computeTodosImportPlanId(conflictRequest),
    }, committed);
    expect(conflict.action).toBe("reject");
    if (conflict.action === "reject") {
      expect(conflict.error.code).toBe("TODOS_IDEMPOTENCY_CONFLICT");
    }

    const planConflict = evaluateTodosImportExecution({
      ...request,
      importPlanDigest: sha256TodosText("different-plan"),
    }, committed);
    expect(planConflict.action).toBe("reject");
    if (planConflict.action === "reject") {
      expect(planConflict.error.code).toBe("TODOS_IDEMPOTENCY_CONFLICT");
    }

    const invalidReceipt = {
      ...receipt,
      receiptDigest: sha256TodosText("substituted-receipt"),
    };
    const invalid = evaluateTodosImportExecution(request, {
      state: "committed",
      receipt: invalidReceipt,
    });
    expect(invalid.action).toBe("reject");
    if (invalid.action === "reject") {
      expect(invalid.error.code).toBe("TODOS_TRANSFER_INVALID");
    }

    expect(evaluateTodosImportExecution(request, { state: "uncommitted" }))
      .toEqual({ action: "commit" });
    for (const unknownContext of [
      null,
      "uncommitted",
      {},
      { state: "unknown" },
      { state: "committed" },
      { state: "uncommitted", receipt },
    ]) {
      expect(TodosTransferExecutionContextSchema.safeParse(unknownContext).success).toBe(false);
      expect(evaluateTodosImportExecution(request, unknownContext).action).toBe("reject");
    }
  });
});
