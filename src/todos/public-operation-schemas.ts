import {
  TODOS_CONTRACT_DIGEST,
} from "./contract";
import {
  createTodosPageSchema,
  createTodosResultSchema,
} from "./errors";
import {
  TODOS_COMMON_SCHEMA_IDS,
  TODOS_COMMON_SCHEMAS,
  TODOS_REQUEST_SCHEMA_IDS,
  TODOS_REQUEST_SCHEMAS as TODOS_STRUCTURAL_REQUEST_SCHEMAS,
  TODOS_RESPONSE_SCHEMA_IDS,
  TODOS_RESPONSE_SCHEMAS as TODOS_STRUCTURAL_RESPONSE_SCHEMAS,
} from "./operation-schemas";
import {
  TODOS_OPERATION_MANIFEST_DIGEST,
} from "./operations";
import {
  TodosMigrationReceiptSchema,
  TodosTransferCheckpointSchema,
} from "./transfer";

export {
  TODOS_COMMON_SCHEMA_IDS,
  TODOS_COMMON_SCHEMAS,
  TODOS_REQUEST_SCHEMA_IDS,
  TODOS_RESPONSE_SCHEMA_IDS,
};

// @todos-runtime-validator operation.public_transfer_import_execute_canonical
const PublicTransferImportExecuteRequestSchema =
  TODOS_STRUCTURAL_REQUEST_SCHEMAS[
    TODOS_REQUEST_SCHEMA_IDS.transferImportExecute
  ].superRefine((value, ctx) => {
    if (value.bundle.contractDigest !== TODOS_CONTRACT_DIGEST) {
      ctx.addIssue({
        code: "custom",
        message: "Transfer bundle must bind the current Todos contract",
        path: ["bundle", "contractDigest"],
      });
    }
    if (value.bundle.manifestDigest !== TODOS_OPERATION_MANIFEST_DIGEST) {
      ctx.addIssue({
        code: "custom",
        message: "Transfer bundle must bind the current Todos operation manifest",
        path: ["bundle", "manifestDigest"],
      });
    }
    if (
      value.checkpoint
      && !TodosTransferCheckpointSchema.safeParse(value.checkpoint).success
    ) {
      ctx.addIssue({
        code: "custom",
        message: "Transfer checkpoint must bind the current Todos contract",
        path: ["checkpoint"],
      });
    }
  });

export const TODOS_REQUEST_SCHEMAS = Object.freeze({
  ...TODOS_STRUCTURAL_REQUEST_SCHEMAS,
  [TODOS_REQUEST_SCHEMA_IDS.transferImportExecute]:
    PublicTransferImportExecuteRequestSchema,
});

export const TODOS_RESPONSE_SCHEMAS = Object.freeze({
  ...TODOS_STRUCTURAL_RESPONSE_SCHEMAS,
  [TODOS_RESPONSE_SCHEMA_IDS.migrationReceiptPage]:
    createTodosResultSchema(createTodosPageSchema(TodosMigrationReceiptSchema)),
  [TODOS_RESPONSE_SCHEMA_IDS.migrationReceipt]:
    createTodosResultSchema(TodosMigrationReceiptSchema),
});
