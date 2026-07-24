import * as z from "zod/v4";
import {
  TODOS_MANIFEST_VERSION,
  TodosAudienceSchema,
  TodosModeSchema,
} from "./common";

export const TODOS_CAPABILITY_SCHEMA_IDS = {
  capability: "hasna.todos.capability.v1",
  manifest: "hasna.todos.capability_manifest.v1",
} as const;

export const TodosCapabilitySchema = z.strictObject({
  id: z.string().min(1).max(128).regex(/^[a-z][a-z0-9-]*$/),
  availability: z.enum(["core", "gated"]),
  operationIds: z.array(z.string().regex(/^todos\.[a-z0-9_]+(?:\.[a-z0-9_]+)+$/)).min(1),
  modes: z.array(TodosModeSchema).min(1),
  audiences: z.array(TodosAudienceSchema).min(1),
});
export type TodosCapability = z.infer<typeof TodosCapabilitySchema>;

export const TodosCapabilityManifestSchema = z.strictObject({
  schema: z.literal(TODOS_CAPABILITY_SCHEMA_IDS.manifest),
  version: z.literal(TODOS_MANIFEST_VERSION),
  manifestDigest: z.string().regex(/^[a-f0-9]{64}$/),
  capabilities: z.array(TodosCapabilitySchema).min(1),
});
export type TodosCapabilityManifest = z.infer<typeof TodosCapabilityManifestSchema>;

export const TODOS_CAPABILITY_SCHEMAS = Object.freeze({
  [TODOS_CAPABILITY_SCHEMA_IDS.capability]: TodosCapabilitySchema,
  [TODOS_CAPABILITY_SCHEMA_IDS.manifest]: TodosCapabilityManifestSchema,
});
