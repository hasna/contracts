import * as z from "zod/v4";
import {
  TodosAudienceSchema,
  TodosEntityIdSchema,
  TodosIdempotencyKeySchema,
  TodosOwnerIdSchema,
  TodosRequestIdSchema,
} from "./common";
import {
  createTodosError,
  type TodosError,
} from "./errors";

export const TODOS_IDENTITY_SCHEMA_ID = "hasna.todos.identity_context.v1" as const;

export const TodosIdentityRoleSchema = z.enum([
  "customer_member",
  "customer_manager",
  "tenant_admin",
]);

export const TodosScopeSchema = z.string()
  .min(1)
  .max(160)
  .regex(/^todos:[a-z0-9_*:-]+$/);

// @todos-runtime-validator identity.context_semantics
export const TodosIdentityContextSchema = z.strictObject({
  issuer: z.string().min(1).max(256),
  audience: TodosAudienceSchema,
  subject: z.string().min(1).max(256),
  organizationId: TodosOwnerIdSchema,
  tenantId: TodosOwnerIdSchema,
  roles: z.array(TodosIdentityRoleSchema).min(1).max(32),
  scopes: z.array(TodosScopeSchema).min(1).max(256),
  keyId: TodosEntityIdSchema,
  tokenId: TodosEntityIdSchema,
  requestId: TodosRequestIdSchema,
  agentId: TodosEntityIdSchema.nullable(),
  sessionId: TodosEntityIdSchema.nullable(),
  projectId: TodosEntityIdSchema.nullable(),
  taskListId: TodosEntityIdSchema.nullable(),
  idempotencyKey: TodosIdempotencyKeySchema.nullable(),
}).superRefine((value, ctx) => {
  if (new Set(value.roles).size !== value.roles.length) {
    ctx.addIssue({
      code: "custom",
      message: "Identity roles must be unique",
      path: ["roles"],
    });
  }
  if (new Set(value.scopes).size !== value.scopes.length) {
    ctx.addIssue({
      code: "custom",
      message: "Identity scopes must be unique",
      path: ["scopes"],
    });
  }
  if (value.audience === "tenant_admin" && !value.roles.includes("tenant_admin")) {
    ctx.addIssue({
      code: "custom",
      message: "The tenant_admin audience requires the tenant_admin role",
      path: ["roles"],
    });
  }
});
export type TodosIdentityContext = z.infer<typeof TodosIdentityContextSchema>;

export interface TodosIdentityRequirements {
  organizationId: string;
  tenantId: string;
  audience: "customer" | "tenant_admin";
  requiredScopes: readonly string[];
  requireIdempotencyKey?: boolean;
}

export type TodosIdentityValidationResult =
  | { success: true; identity: TodosIdentityContext }
  | { success: false; error: TodosError };

function scopeMatches(granted: string, required: string): boolean {
  if (granted === "todos:*" || granted === required) {
    return true;
  }
  const grantedParts = granted.split(":");
  const requiredParts = required.split(":");
  if (grantedParts.length !== requiredParts.length) {
    return false;
  }
  return grantedParts.every((part, index) => part === "*" || part === requiredParts[index]);
}

// @todos-runtime-validator identity.authorization_binding
export function validateTodosIdentityContext(
  input: unknown,
  requirements: TodosIdentityRequirements,
): TodosIdentityValidationResult {
  const parsed = TodosIdentityContextSchema.safeParse(input);
  if (!parsed.success) {
    return {
      success: false,
      error: createTodosError("TODOS_AUTHENTICATION_FAILED", "Identity context is invalid", {
        details: parsed.error.issues.map((issue) => ({
          field: issue.path.join(".") || null,
          reason: issue.message,
        })),
      }),
    };
  }

  const identity = parsed.data;
  if (
    identity.organizationId !== requirements.organizationId
    || identity.tenantId !== requirements.tenantId
  ) {
    return {
      success: false,
      error: createTodosError("TODOS_TENANT_MISMATCH", "Identity tenant binding does not match the requested tenant"),
    };
  }

  const audienceAllowed = identity.audience === requirements.audience
    || (identity.audience === "tenant_admin" && requirements.audience === "customer");
  if (!audienceAllowed) {
    return {
      success: false,
      error: createTodosError("TODOS_ACCESS_DENIED", "Identity audience cannot access this operation"),
    };
  }

  const missingScopes = requirements.requiredScopes.filter(
    (required) => !identity.scopes.some((granted) => scopeMatches(granted, required)),
  );
  if (missingScopes.length > 0) {
    return {
      success: false,
      error: createTodosError("TODOS_SCOPE_REQUIRED", "Identity lacks required scopes", {
        details: missingScopes.map((scope) => ({
          field: "scopes",
          reason: "Required scope is missing",
          expected: scope,
        })),
      }),
    };
  }

  if (requirements.requireIdempotencyKey === true && identity.idempotencyKey === null) {
    return {
      success: false,
      error: createTodosError("TODOS_IDEMPOTENCY_REQUIRED", "This operation requires an idempotency key"),
    };
  }

  return { success: true, identity };
}
