import * as z from "zod/v4";
import {
  TODOS_CONTRACT_VERSION,
  TODOS_MANIFEST_VERSION,
  TodosModeSchema,
  TodosOwnerIdSchema,
  TodosSha256DigestSchema,
  TodosTimestampSchema,
} from "./common";

export const TODOS_AUTHORITY_SCHEMA_IDS = {
  config: "hasna.todos.authority_config.v1",
  handshake: "hasna.todos.authority_handshake.v1",
  serviceStatus: "hasna.todos.service_status.v1",
} as const;

export const TodosAuthorityDescriptorSchema = z.strictObject({
  id: TodosOwnerIdSchema,
  kind: z.enum(["local_installation", "cloud_tenant"]),
  endpoint: z.url().nullable(),
});
export type TodosAuthorityDescriptor = z.infer<typeof TodosAuthorityDescriptorSchema>;

const TodosAuthorityConfigShape = {
  mode: TodosModeSchema,
  authority: TodosAuthorityDescriptorSchema,
  contractVersion: z.literal(TODOS_CONTRACT_VERSION),
  contractDigest: TodosSha256DigestSchema,
  manifestVersion: z.literal(TODOS_MANIFEST_VERSION),
  manifestDigest: TodosSha256DigestSchema,
  capabilityIds: z.array(z.string().min(1).max(128).regex(/^[a-z][a-z0-9-]*$/)).min(1),
} as const;

function enforceTodosAuthorityInvariants(
  value: z.infer<z.ZodObject<typeof TodosAuthorityConfigShape>>,
  ctx: z.RefinementCtx,
): void {
  if (new Set(value.capabilityIds).size !== value.capabilityIds.length) {
    ctx.addIssue({
      code: "custom",
      message: "Capability ids must be unique",
      path: ["capabilityIds"],
    });
  }
  if (value.mode === "local") {
    if (value.authority.kind !== "local_installation" || value.authority.endpoint !== null) {
      ctx.addIssue({
        code: "custom",
        message: "Local mode requires a local installation authority without a network endpoint",
        path: ["authority"],
      });
    }
  } else if (
    value.authority.kind !== "cloud_tenant"
    || value.authority.endpoint === null
    || !value.authority.endpoint.startsWith("https://")
  ) {
    ctx.addIssue({
      code: "custom",
      message: "Cloud mode requires a tenant authority with an HTTPS endpoint",
      path: ["authority"],
    });
  }
}

// @todos-runtime-validator authority.config_semantics
export const TodosAuthorityConfigSchema = z
  .strictObject(TodosAuthorityConfigShape)
  .superRefine(enforceTodosAuthorityInvariants);
export type TodosAuthorityConfig = z.infer<typeof TodosAuthorityConfigSchema>;

// @todos-runtime-validator authority.handshake_semantics
export const TodosAuthorityHandshakeSchema = z
  .strictObject({
    ...TodosAuthorityConfigShape,
    issuedAt: TodosTimestampSchema,
  })
  .superRefine(enforceTodosAuthorityInvariants);
export type TodosAuthorityHandshake = z.infer<typeof TodosAuthorityHandshakeSchema>;

export const TodosServiceStatusSchema = z.strictObject({
  status: z.enum(["healthy", "ready", "unavailable"]),
  mode: TodosModeSchema,
  authorityId: TodosOwnerIdSchema,
  contractVersion: z.literal(TODOS_CONTRACT_VERSION),
  manifestVersion: z.literal(TODOS_MANIFEST_VERSION),
  observedAt: TodosTimestampSchema,
});
export type TodosServiceStatus = z.infer<typeof TodosServiceStatusSchema>;

export const TODOS_AUTHORITY_SCHEMAS = Object.freeze({
  [TODOS_AUTHORITY_SCHEMA_IDS.config]: TodosAuthorityConfigSchema,
  [TODOS_AUTHORITY_SCHEMA_IDS.handshake]: TodosAuthorityHandshakeSchema,
  [TODOS_AUTHORITY_SCHEMA_IDS.serviceStatus]: TodosServiceStatusSchema,
});
