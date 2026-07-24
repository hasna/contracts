import * as z from "zod/v4";
import {
  TodosModeSchema,
  TodosOwnerIdSchema,
  TodosSha256DigestSchema,
} from "./common";
import {
  TodosIdentityContextSchema,
} from "./identity";

export const TODOS_OPERATION_INVOCATION_SCHEMA_ID = "hasna.todos.operation_invocation.v1" as const;

const TodosOperationIdSchema = z.string().regex(/^todos\.[a-z0-9_]+(?:\.[a-z0-9_]+)+$/);

/**
 * Version-neutral JSON shape used for schema hashing and generated JSON Schema.
 * The public TodosOperationInvocationSchema adds canonical runtime refinements.
 */
export const TodosOperationInvocationEnvelopeSchema = z.strictObject({
  mode: TodosModeSchema,
  authorityId: TodosOwnerIdSchema,
  contractDigest: TodosSha256DigestSchema,
  manifestDigest: TodosSha256DigestSchema,
  operationId: TodosOperationIdSchema,
  identity: TodosIdentityContextSchema,
  request: z.unknown(),
});
export type TodosOperationInvocationEnvelope = z.infer<typeof TodosOperationInvocationEnvelopeSchema>;
