import * as z from "zod/v4";
import {
  TODOS_CONTRACT_DIGEST,
} from "./contract";
import {
  createTodosError,
  type TodosError,
} from "./errors";
import {
  TodosIdentityContextSchema,
  validateTodosIdentityContext,
} from "./identity";
import {
  TODOS_OPERATION_INVOCATION_SCHEMA_ID,
  TodosOperationInvocationEnvelopeSchema,
} from "./invocation-envelope";
import {
  TODOS_REQUEST_SCHEMAS,
} from "./operation-schemas";
import {
  TODOS_OPERATION_MANIFEST_DIGEST,
  getTodosOperation,
  type TodosOperation,
} from "./operations";
import {
  validateTodosTransferBundle,
} from "./transfer";

/**
 * One protocol-neutral invocation envelope. Operation and idempotency semantics
 * are resolved from TODOS_OPERATION_MANIFEST; this schema deliberately does not
 * define a second operation vocabulary.
 */
// @todos-runtime-validator invocation.operation_binding
export const TodosOperationInvocationSchema =
  TodosOperationInvocationEnvelopeSchema.superRefine((value, ctx) => {
  if (value.contractDigest !== TODOS_CONTRACT_DIGEST) {
    ctx.addIssue({
      code: "custom",
      message: "Invocation contract digest does not match this contract",
      path: ["contractDigest"],
    });
  }
  if (value.manifestDigest !== TODOS_OPERATION_MANIFEST_DIGEST) {
    ctx.addIssue({
      code: "custom",
      message: "Invocation manifest digest does not match this operation manifest",
      path: ["manifestDigest"],
    });
  }
  if (
    value.authorityId !== value.identity.organizationId
    || value.authorityId !== value.identity.tenantId
  ) {
    ctx.addIssue({
      code: "custom",
      message: "Invocation authority must match the validated identity tenant",
      path: ["authorityId"],
    });
  }

  const operation = getTodosOperation(value.operationId);
  if (!operation) {
    ctx.addIssue({
      code: "custom",
      message: "Invocation operation is not declared by the operation manifest",
      path: ["operationId"],
    });
    return;
  }
  if (!operation.supportedModes.includes(value.mode)) {
    ctx.addIssue({
      code: "custom",
      message: "Invocation mode is not supported by this operation",
      path: ["mode"],
    });
  }

  const identityResult = validateTodosIdentityContext(value.identity, {
    organizationId: value.authorityId,
    tenantId: value.authorityId,
    audience: operation.audience,
    requiredScopes: operation.requiredScopes,
    requireIdempotencyKey: operation.idempotency === "required",
  });
  if (!identityResult.success) {
    ctx.addIssue({
      code: "custom",
      message: `${identityResult.error.code}: ${identityResult.error.message}`,
      path: ["identity"],
    });
  }

  const requestSchema = (TODOS_REQUEST_SCHEMAS as Readonly<Record<string, z.ZodType>>)[operation.requestSchemaId];
  if (!requestSchema) {
    ctx.addIssue({
      code: "custom",
      message: "Operation request schema is not registered",
      path: ["operationId"],
    });
    return;
  }
  const requestResult = requestSchema.safeParse(value.request);
  if (!requestResult.success) {
    for (const issue of requestResult.error.issues) {
      ctx.addIssue({
        code: "custom",
        message: issue.message,
        path: ["request", ...issue.path],
      });
    }
    return;
  }

  if (
    operation.id === "todos.transfer.validate"
    || operation.id === "todos.transfer.import_preview"
    || operation.id === "todos.transfer.import_execute"
  ) {
    const request = requestResult.data as {
      bundle: {
        contractDigest: string;
        manifestDigest: string;
      };
      targetAuthorityId?: string;
      checkpoint?: {
        idempotencyKey: string;
      } | null;
    };
    if (
      request.bundle.contractDigest !== value.contractDigest
      || request.bundle.manifestDigest !== value.manifestDigest
    ) {
      ctx.addIssue({
        code: "custom",
        message: "Transfer bundle digests must match the canonical invocation digests",
        path: ["request", "bundle"],
      });
    }
    if (
      request.targetAuthorityId !== undefined
      && request.targetAuthorityId !== value.authorityId
    ) {
      ctx.addIssue({
        code: "custom",
        message: "Transfer target authority must match the invocation authority",
        path: ["request", "targetAuthorityId"],
      });
    }
    if (
      request.checkpoint
      && request.checkpoint.idempotencyKey !== value.identity.idempotencyKey
    ) {
      ctx.addIssue({
        code: "custom",
        message: "Transfer checkpoint idempotency must match the invocation identity",
        path: ["request", "checkpoint", "idempotencyKey"],
      });
    }
    if (!validateTodosTransferBundle(request.bundle).valid) {
      ctx.addIssue({
        code: "custom",
        message: "Transfer operations require a canonical, fully valid bundle",
        path: ["request", "bundle"],
      });
    }
  }
  });
export type TodosOperationInvocation = z.infer<typeof TodosOperationInvocationSchema>;

export type TodosOperationInvocationValidation =
  | {
    success: true;
    invocation: TodosOperationInvocation;
    operation: TodosOperation;
  }
  | {
    success: false;
    error: TodosError;
  };

// @todos-runtime-validator invocation.validate_operation
export function validateTodosOperationInvocation(
  input: unknown,
): TodosOperationInvocationValidation {
  const parsed = TodosOperationInvocationSchema.safeParse(input);
  if (!parsed.success) {
    return {
      success: false,
      error: createTodosError("TODOS_INVALID_INPUT", "Todos operation invocation is invalid", {
        details: parsed.error.issues.map((issue) => ({
          field: issue.path.join(".") || null,
          reason: issue.message,
        })),
      }),
    };
  }
  const operation = getTodosOperation(parsed.data.operationId);
  if (!operation) {
    return {
      success: false,
      error: createTodosError("TODOS_OPERATION_UNSUPPORTED", "Todos operation is not declared"),
    };
  }
  return {
    success: true,
    invocation: parsed.data,
    operation,
  };
}

export const TODOS_INVOCATION_SCHEMAS = Object.freeze({
  [TODOS_OPERATION_INVOCATION_SCHEMA_ID]: TodosOperationInvocationSchema,
});

export {
  TODOS_OPERATION_INVOCATION_SCHEMA_ID,
};
