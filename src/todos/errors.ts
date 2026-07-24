import * as z from "zod/v4";
import {
  TodosPortableScalarSchema,
  TodosRequestIdSchema,
} from "./common";

export const TODOS_ERROR_CODES = [
  "TODOS_INVALID_INPUT",
  "TODOS_INVALID_MODE",
  "TODOS_AUTHENTICATION_FAILED",
  "TODOS_SCOPE_REQUIRED",
  "TODOS_TENANT_MISMATCH",
  "TODOS_ACCESS_DENIED",
  "TODOS_NOT_FOUND",
  "TODOS_AMBIGUOUS_REFERENCE",
  "TODOS_VERSION_CONFLICT",
  "TODOS_RESOURCE_CONFLICT",
  "TODOS_LOCK_CONFLICT",
  "TODOS_PRECONDITION_FAILED",
  "TODOS_APPROVAL_REQUIRED",
  "TODOS_CAPABILITY_REQUIRED",
  "TODOS_OPERATION_UNSUPPORTED",
  "TODOS_IDEMPOTENCY_REQUIRED",
  "TODOS_IDEMPOTENCY_CONFLICT",
  "TODOS_RATE_LIMITED",
  "TODOS_QUOTA_EXCEEDED",
  "TODOS_UPGRADE_REQUIRED",
  "TODOS_AUTHORITY_MISMATCH",
  "TODOS_AUTHORITY_UNAVAILABLE",
  "TODOS_INTERNAL",
  "TODOS_TRANSFER_INVALID",
  "TODOS_TRANSFER_CHECKSUM_MISMATCH",
  "TODOS_TRANSFER_REFERENCE_MISSING",
  "TODOS_PROJECTION_PREDECESSOR_CONFLICT",
] as const;

export const TodosErrorCodeSchema = z.enum(TODOS_ERROR_CODES);
export type TodosErrorCode = z.infer<typeof TodosErrorCodeSchema>;

export const TodosErrorDetailSchema = z.strictObject({
  field: z.string().min(1).max(256).nullable(),
  reason: z.string().min(1).max(1024),
  expected: TodosPortableScalarSchema.optional(),
  actual: TodosPortableScalarSchema.optional(),
});
export type TodosErrorDetail = z.infer<typeof TodosErrorDetailSchema>;

export const TodosErrorSchema = z.strictObject({
  code: TodosErrorCodeSchema,
  message: z.string().min(1).max(2048),
  retryable: z.boolean(),
  details: z.array(TodosErrorDetailSchema).max(100),
});
export type TodosError = z.infer<typeof TodosErrorSchema>;

export const TodosTransportMetaSchema = z.strictObject({
  requestId: TodosRequestIdSchema,
  httpStatus: z.number().int().min(100).max(599).nullable(),
  retryAfterSeconds: z.number().int().nonnegative().nullable(),
});
export type TodosTransportMeta = z.infer<typeof TodosTransportMetaSchema>;

export const TodosErrorEnvelopeSchema = z.strictObject({
  ok: z.literal(false),
  error: TodosErrorSchema,
  transport: TodosTransportMetaSchema,
});
export type TodosErrorEnvelope = z.infer<typeof TodosErrorEnvelopeSchema>;

const RETRYABLE_ERRORS = new Set<TodosErrorCode>([
  "TODOS_LOCK_CONFLICT",
  "TODOS_RATE_LIMITED",
  "TODOS_AUTHORITY_UNAVAILABLE",
  "TODOS_INTERNAL",
]);

export function createTodosError(
  code: TodosErrorCode,
  message: string,
  options: {
    retryable?: boolean;
    details?: TodosErrorDetail[];
  } = {},
): TodosError {
  return TodosErrorSchema.parse({
    code,
    message,
    retryable: options.retryable ?? RETRYABLE_ERRORS.has(code),
    details: options.details ?? [],
  });
}

export interface TodosErrorCatalogEntry {
  code: TodosErrorCode;
  transportStatus: number;
  retryable: boolean;
}

const ERROR_STATUS: Record<TodosErrorCode, number> = {
  TODOS_INVALID_INPUT: 400,
  TODOS_INVALID_MODE: 400,
  TODOS_AUTHENTICATION_FAILED: 401,
  TODOS_SCOPE_REQUIRED: 403,
  TODOS_TENANT_MISMATCH: 403,
  TODOS_ACCESS_DENIED: 403,
  TODOS_NOT_FOUND: 404,
  TODOS_AMBIGUOUS_REFERENCE: 409,
  TODOS_VERSION_CONFLICT: 409,
  TODOS_RESOURCE_CONFLICT: 409,
  TODOS_LOCK_CONFLICT: 409,
  TODOS_PRECONDITION_FAILED: 412,
  TODOS_APPROVAL_REQUIRED: 403,
  TODOS_CAPABILITY_REQUIRED: 403,
  TODOS_OPERATION_UNSUPPORTED: 405,
  TODOS_IDEMPOTENCY_REQUIRED: 400,
  TODOS_IDEMPOTENCY_CONFLICT: 409,
  TODOS_RATE_LIMITED: 429,
  TODOS_QUOTA_EXCEEDED: 429,
  TODOS_UPGRADE_REQUIRED: 426,
  TODOS_AUTHORITY_MISMATCH: 409,
  TODOS_AUTHORITY_UNAVAILABLE: 503,
  TODOS_INTERNAL: 500,
  TODOS_TRANSFER_INVALID: 422,
  TODOS_TRANSFER_CHECKSUM_MISMATCH: 422,
  TODOS_TRANSFER_REFERENCE_MISSING: 422,
  TODOS_PROJECTION_PREDECESSOR_CONFLICT: 409,
};

export const TODOS_ERROR_CATALOG: readonly TodosErrorCatalogEntry[] = Object.freeze(
  TODOS_ERROR_CODES.map((code) => ({
    code,
    transportStatus: ERROR_STATUS[code],
    retryable: RETRYABLE_ERRORS.has(code),
  })),
);

export function getTodosErrorCatalogEntry(code: TodosErrorCode): TodosErrorCatalogEntry {
  const entry = TODOS_ERROR_CATALOG.find((candidate) => candidate.code === code);
  if (!entry) {
    throw new Error(`Unknown Todos error code: ${code}`);
  }
  return entry;
}

export function createTodosResultSchema<const T extends z.ZodType>(dataSchema: T) {
  return z.discriminatedUnion("ok", [
    z.strictObject({
      ok: z.literal(true),
      data: dataSchema,
      requestId: TodosRequestIdSchema,
    }),
    z.strictObject({
      ok: z.literal(false),
      error: TodosErrorSchema,
      requestId: TodosRequestIdSchema,
    }),
  ]);
}

// @todos-runtime-validator response.page_count
export function createTodosPageSchema<const T extends z.ZodType>(itemSchema: T) {
  return z.strictObject({
    items: z.array(itemSchema),
    count: z.number().int().nonnegative(),
    nextCursor: z.string().min(1).max(512).nullable(),
  }).superRefine((value, ctx) => {
    if (value.count !== value.items.length) {
      ctx.addIssue({
        code: "custom",
        message: "Page count must equal the number of returned items",
        path: ["count"],
      });
    }
  });
}

export const TodosMutationReceiptSchema = z.strictObject({
  operationId: z.string().regex(/^todos\.[a-z0-9_]+(?:\.[a-z0-9_]+)+$/),
  resourceId: z.string().min(1).max(160),
  changed: z.boolean(),
  replayed: z.boolean(),
  version: z.number().int().positive().nullable(),
});
export type TodosMutationReceipt = z.infer<typeof TodosMutationReceiptSchema>;
