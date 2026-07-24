import * as z from "zod/v4";
import {
  TODOS_CONTRACT_DIGEST,
} from "./contract";
import {
  TODOS_OPERATION_MANIFEST_DIGEST,
} from "./operations";
import {
  createTodosError,
} from "./errors";
import {
  TODOS_TRANSFER_SCHEMA_IDS,
  TODOS_TRANSFER_SCHEMAS as TODOS_TRANSFER_STRUCTURAL_SCHEMAS,
  TodosMigrationReceiptSchema as TodosMigrationReceiptStructuralSchema,
  TodosTransferBundleSchema,
  TodosTransferCheckpointSchema as TodosTransferCheckpointStructuralSchema,
  TodosTransferImportExecutionSchema as TodosTransferImportExecutionStructuralSchema,
  TodosTransferValidationSchema,
  createTodosMigrationReceipt as createTodosMigrationReceiptIntegrity,
  createTodosTransferBundleWithDigests,
  createTodosTransferCheckpoint as createTodosTransferCheckpointIntegrity,
  createTodosTransferImportPreviewIntegrity,
  evaluateTodosImportExecutionIntegrity,
  validateTodosMigrationReceiptChain as validateTodosMigrationReceiptChainIntegrity,
  validateTodosTransferBundleIntegrity,
  validateTodosTransferCheckpointTransition as validateTodosTransferCheckpointTransitionIntegrity,
  type TodosImportExecutionDecision,
  type TodosTransferBundle,
  type TodosTransferBundleWithDigestsInput,
  type TodosTransferConflict,
  type TodosTransferImportPreview,
  type TodosTransferValidation,
} from "./transfer-schema";

export {
  TODOS_TRANSFER_CLASSIFICATION,
  TODOS_TRANSFER_SCHEMA_IDS,
  TODOS_TRANSFER_SECTION_NAMES,
  TodosAttachmentContentReferenceSchema,
  TodosDependencyClosureEntrySchema,
  TodosPortableCommandReceiptSchema,
  TodosPortableGitCommitSchema,
  TodosPortableRunArtifactSchema,
  TodosPortableRunCommandSchema,
  TodosPortableRunFileSchema,
  TodosPortableTaskFileSchema,
  TodosPortableVerificationEvidenceSchema,
  TodosTransferBundleSchema,
  TodosTransferConflictSchema,
  TodosTransferImportPreviewSchema,
  TodosTransferIssueSchema,
  TodosTransferRecordRefSchema,
  TodosTransferReferenceClosureEntrySchema,
  TodosTransferReferenceOnlySchema,
  TodosTransferRepairIssueSchema,
  TodosTransferSectionNameSchema,
  TodosTransferSectionsSchema,
  TodosTransferValidationSchema,
  computeTodosDependencyClosure,
  computeTodosImportPlanId,
  computeTodosTransferBundleChecksum,
  computeTodosTransferReferenceClosure,
} from "./transfer-schema";
export type {
  TodosAttachmentContentReference,
  TodosDependencyClosureEntry,
  TodosImportExecutionDecision,
  TodosImportPlanIdentityInput,
  TodosMigrationReceipt,
  TodosMigrationReceiptChainValidation,
  TodosMigrationReceiptInput,
  TodosPortableCommandReceipt,
  TodosPortableGitCommit,
  TodosPortableRunArtifact,
  TodosPortableRunCommand,
  TodosPortableRunFile,
  TodosPortableTaskFile,
  TodosPortableVerificationEvidence,
  TodosTransferBundle,
  TodosTransferBundleUnsigned,
  TodosTransferCheckpoint,
  TodosTransferCheckpointInput,
  TodosTransferConflict,
  TodosTransferExecutionContext,
  TodosTransferImportExecution,
  TodosTransferImportPreview,
  TodosTransferIssue,
  TodosTransferRecordRef,
  TodosTransferReferenceClosureEntry,
  TodosTransferReferenceOnly,
  TodosTransferRepairIssue,
  TodosTransferSectionName,
  TodosTransferSections,
  TodosTransferValidation,
} from "./transfer-schema";

function requireCanonicalTransferDigests(
  value: {
    contractDigest: string;
    manifestDigest: string;
  },
  ctx: z.RefinementCtx,
): void {
  if (value.contractDigest !== TODOS_CONTRACT_DIGEST) {
    ctx.addIssue({
      code: "custom",
      message: "Contract digest must match the current Todos contract",
      path: ["contractDigest"],
    });
  }
  if (value.manifestDigest !== TODOS_OPERATION_MANIFEST_DIGEST) {
    ctx.addIssue({
      code: "custom",
      message: "Manifest digest must match the current Todos operation manifest",
      path: ["manifestDigest"],
    });
  }
}

// @todos-runtime-validator transfer.public_checkpoint_canonical
export const TodosTransferCheckpointSchema =
  TodosTransferCheckpointStructuralSchema.superRefine(
    requireCanonicalTransferDigests,
  );

// @todos-runtime-validator transfer.public_receipt_canonical
export const TodosMigrationReceiptSchema =
  TodosMigrationReceiptStructuralSchema.superRefine((value, ctx) => {
    requireCanonicalTransferDigests(value, ctx);
    if (!TodosTransferCheckpointSchema.safeParse(value.checkpoint).success) {
      ctx.addIssue({
        code: "custom",
        message: "Receipt checkpoint must bind the current Todos contract",
        path: ["checkpoint"],
      });
    }
  });

// @todos-runtime-validator transfer.public_execution_request_canonical
export const TodosTransferImportExecutionSchema =
  TodosTransferImportExecutionStructuralSchema.superRefine((value, ctx) => {
    requireCanonicalTransferDigests(value, ctx);
    if (
      value.checkpoint
      && !TodosTransferCheckpointSchema.safeParse(value.checkpoint).success
    ) {
      ctx.addIssue({
        code: "custom",
        message: "Execution checkpoint must bind the current Todos contract",
        path: ["checkpoint"],
      });
    }
  });

export const TodosTransferExecutionContextSchema = z.discriminatedUnion("state", [
  z.strictObject({
    state: z.literal("uncommitted"),
  }),
  z.strictObject({
    state: z.literal("committed"),
    receipt: TodosMigrationReceiptSchema,
  }),
]);

export const TODOS_TRANSFER_SCHEMAS = Object.freeze({
  ...TODOS_TRANSFER_STRUCTURAL_SCHEMAS,
  [TODOS_TRANSFER_SCHEMA_IDS.importExecution]: TodosTransferImportExecutionSchema,
  [TODOS_TRANSFER_SCHEMA_IDS.executionContext]: TodosTransferExecutionContextSchema,
  [TODOS_TRANSFER_SCHEMA_IDS.checkpoint]: TodosTransferCheckpointSchema,
  [TODOS_TRANSFER_SCHEMA_IDS.migrationReceipt]: TodosMigrationReceiptSchema,
});

export interface TodosTransferBundleInput
  extends Omit<TodosTransferBundleWithDigestsInput, "contractDigest" | "manifestDigest"> {}

export function createTodosTransferBundle(
  input: TodosTransferBundleInput,
): TodosTransferBundle {
  return createTodosTransferBundleWithDigests({
    ...input,
    contractDigest: TODOS_CONTRACT_DIGEST,
    manifestDigest: TODOS_OPERATION_MANIFEST_DIGEST,
  });
}

// @todos-runtime-validator transfer.canonical_digests
export function validateTodosTransferBundle(input: unknown): TodosTransferValidation {
  const validation = validateTodosTransferBundleIntegrity(input);
  const parsed = TodosTransferBundleSchema.safeParse(input);
  if (!parsed.success) return validation;

  const issues = [...validation.issues];
  if (parsed.data.contractDigest !== TODOS_CONTRACT_DIGEST) {
    issues.push({
      code: "canonical_digest_mismatch",
      path: "contractDigest",
      message: "Bundle contract digest does not match the current Todos contract",
      repairable: false,
    });
  }
  if (parsed.data.manifestDigest !== TODOS_OPERATION_MANIFEST_DIGEST) {
    issues.push({
      code: "canonical_digest_mismatch",
      path: "manifestDigest",
      message: "Bundle manifest digest does not match the current Todos operation manifest",
      repairable: false,
    });
  }
  return TodosTransferValidationSchema.parse({
    ...validation,
    valid: issues.length === 0,
    issues,
  });
}

export function createTodosTransferImportPreview(
  bundle: TodosTransferBundle,
  targetAuthorityId: string,
  conflicts: TodosTransferConflict[] = [],
): TodosTransferImportPreview {
  return createTodosTransferImportPreviewIntegrity(
    bundle,
    targetAuthorityId,
    conflicts,
    validateTodosTransferBundle(bundle),
  );
}

export function createTodosTransferCheckpoint(
  input: Parameters<typeof createTodosTransferCheckpointIntegrity>[0],
): ReturnType<typeof createTodosTransferCheckpointIntegrity> {
  return TodosTransferCheckpointSchema.parse(
    createTodosTransferCheckpointIntegrity(input),
  );
}

// @todos-runtime-validator transfer.public_checkpoint_transition
export function validateTodosTransferCheckpointTransition(
  previousInput: unknown,
  currentInput: unknown,
): boolean {
  const previous = TodosTransferCheckpointSchema.safeParse(previousInput);
  const current = TodosTransferCheckpointSchema.safeParse(currentInput);
  return previous.success
    && current.success
    && validateTodosTransferCheckpointTransitionIntegrity(
      previous.data,
      current.data,
    );
}

export function createTodosMigrationReceipt(
  input: Parameters<typeof createTodosMigrationReceiptIntegrity>[0],
): ReturnType<typeof createTodosMigrationReceiptIntegrity> {
  return TodosMigrationReceiptSchema.parse(
    createTodosMigrationReceiptIntegrity(input),
  );
}

// @todos-runtime-validator transfer.public_receipt_chain
export function validateTodosMigrationReceiptChain(
  input: unknown,
): ReturnType<typeof validateTodosMigrationReceiptChainIntegrity> {
  if (!Array.isArray(input)) {
    return {
      success: false,
      action: "conflict",
      issues: ["Receipt chain must be an array"],
    };
  }
  const receipts: z.infer<typeof TodosMigrationReceiptSchema>[] = [];
  const issues: string[] = [];
  for (const [index, value] of input.entries()) {
    const parsed = TodosMigrationReceiptSchema.safeParse(value);
    if (!parsed.success) {
      issues.push(
        ...parsed.error.issues.map(
          (issue) => `receipts.${index}.${issue.path.join(".")}: ${issue.message}`,
        ),
      );
    } else {
      receipts.push(parsed.data);
    }
  }
  return issues.length > 0
    ? { success: false, action: "conflict", issues }
    : validateTodosMigrationReceiptChainIntegrity(receipts);
}

// @todos-runtime-validator transfer.canonical_execution
export function evaluateTodosImportExecution(
  requestInput: unknown,
  contextInput: unknown,
): TodosImportExecutionDecision {
  const request = TodosTransferImportExecutionSchema.safeParse(requestInput);
  const context = TodosTransferExecutionContextSchema.safeParse(contextInput);
  if (!request.success || !context.success) {
    return {
      action: "reject",
      error: createTodosError(
        "TODOS_TRANSFER_INVALID",
        "Import execution request is not bound to the current Todos contract",
      ),
    };
  }
  return evaluateTodosImportExecutionIntegrity(request.data, context.data);
}

export const TODOS_CANONICAL_TRANSFER_BINDING = Object.freeze({
  schema: TODOS_TRANSFER_SCHEMA_IDS.bundle,
  contractDigest: TODOS_CONTRACT_DIGEST,
  manifestDigest: TODOS_OPERATION_MANIFEST_DIGEST,
});
