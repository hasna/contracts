import { createHash } from "node:crypto";
import * as z from "zod/v4";

export const TODOS_CONTRACT_NAMESPACE = "hasna.todos" as const;
export const TODOS_CONTRACT_VERSION = "1.0.0" as const;
export const TODOS_MANIFEST_VERSION = "1" as const;
export const TODOS_TRANSFER_VERSION = "1" as const;

export const TodosModeSchema = z.enum(["local", "cloud"]);
export type TodosMode = z.infer<typeof TodosModeSchema>;

export const TodosAudienceSchema = z.enum(["customer", "tenant_admin"]);
export type TodosAudience = z.infer<typeof TodosAudienceSchema>;

export const TodosTimestampSchema = z.iso.datetime({ offset: true });
export const TodosDateSchema = z.iso.date();
export const TodosEntityIdSchema = z.string().min(1).max(160).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
export const TodosOwnerIdSchema = z.string().min(2).max(128).regex(/^[a-z][a-z0-9.-]*$/);
export const TodosSlugSchema = z.string().min(1).max(96).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
export const TodosRequestIdSchema = z.string().min(8).max(160).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
export const TodosIdempotencyKeySchema = z.string().min(8).max(160).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
export const TodosSha256DigestSchema = z.string().regex(/^[a-f0-9]{64}$/);
export const TodosCursorSchema = z.string().min(1).max(512);
// @todos-runtime-validator common.relative_path_semantics
export const TodosRelativePathSchema = z.string().min(1).max(1024).superRefine((value, ctx) => {
  if (
    value.startsWith("/")
    || value.startsWith("\\")
    || value.includes("\\")
    || value.split("/").some((segment) => segment === "..")
  ) {
    ctx.addIssue({
      code: "custom",
      message: "Paths must be relative and must not traverse parent directories",
    });
  }
});

export const TodosPortableScalarSchema = z.union([
  z.string().max(4096),
  z.number().finite(),
  z.boolean(),
  z.null(),
]);
export type TodosPortableScalar = z.infer<typeof TodosPortableScalarSchema>;

export const TodosOwnerQualifiedRefSchema = z.strictObject({
  owner: TodosOwnerIdSchema,
  kind: z.string().min(1).max(64).regex(/^[a-z][a-z0-9_]*$/),
  id: TodosEntityIdSchema,
  digest: TodosSha256DigestSchema,
});
export type TodosOwnerQualifiedRef = z.infer<typeof TodosOwnerQualifiedRefSchema>;

export const TodosContentRefSchema = z.strictObject({
  algorithm: z.literal("sha256"),
  digest: TodosSha256DigestSchema,
  mediaType: z.string().min(1).max(160),
  byteLength: z.number().int().nonnegative(),
});
export type TodosContentRef = z.infer<typeof TodosContentRefSchema>;

export const TodosPageRequestSchema = z.strictObject({
  cursor: TodosCursorSchema.nullable(),
  limit: z.number().int().positive().max(500),
});
export type TodosPageRequest = z.infer<typeof TodosPageRequestSchema>;

export const TodosResponseMetaSchema = z.strictObject({
  requestId: TodosRequestIdSchema,
  authorityId: TodosOwnerIdSchema,
  contractVersion: z.literal(TODOS_CONTRACT_VERSION),
  manifestVersion: z.literal(TODOS_MANIFEST_VERSION),
});
export type TodosResponseMeta = z.infer<typeof TodosResponseMetaSchema>;

export function canonicalizeTodosValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalizeTodosValue);
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, canonicalizeTodosValue(record[key])]),
    );
  }
  return value;
}

export function stableTodosJson(value: unknown): string {
  return JSON.stringify(canonicalizeTodosValue(value));
}

export function sha256TodosValue(value: unknown): string {
  return createHash("sha256").update(stableTodosJson(value), "utf8").digest("hex");
}

export function sha256TodosText(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function uniqueSortedTodosStrings(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

export function sortTodosRecords<T>(records: readonly T[]): T[] {
  return [...records].sort((left, right) => stableTodosJson(left).localeCompare(stableTodosJson(right)));
}
