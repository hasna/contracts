import * as z from "zod/v4";
import {
  TODOS_CONTRACT_VERSION,
  TODOS_MANIFEST_VERSION,
  sha256TodosValue,
} from "./common";
import {
  TODOS_INVOCATION_SCHEMAS,
} from "./invocation";
import {
  TODOS_INVARIANT_REGISTRY,
  TODOS_INVARIANT_REGISTRY_DIGEST,
} from "./invariants";
import {
  TODOS_SCHEMA_BUNDLE_DIGEST,
  TODOS_SCHEMA_FOUNDATION_REGISTRY,
  buildTodosJsonSchemas,
} from "./schema-foundation";

export const TODOS_SCHEMA_REGISTRY: Readonly<Record<string, z.ZodType>> = Object.freeze({
  ...TODOS_SCHEMA_FOUNDATION_REGISTRY,
  ...TODOS_INVOCATION_SCHEMAS,
});

export type TodosSchemaId = keyof typeof TODOS_SCHEMA_REGISTRY;

export interface TodosSchemaBundle {
  schema: "hasna.todos.schema_bundle.v1";
  contractVersion: typeof TODOS_CONTRACT_VERSION;
  manifestVersion: typeof TODOS_MANIFEST_VERSION;
  schemaDigest: string;
  invariantRegistryDigest: string;
  runtimeValidationRequired: true;
  invariants: typeof TODOS_INVARIANT_REGISTRY;
  schemas: Record<string, Record<string, unknown>>;
}

export function getTodosSchema(schemaId: string): z.ZodType | undefined {
  return TODOS_SCHEMA_REGISTRY[schemaId];
}

export function parseTodosSchema<T = unknown>(schemaId: string, input: unknown): T {
  const schema = getTodosSchema(schemaId);
  if (!schema) {
    throw new Error(`Unknown Todos schema id: ${schemaId}`);
  }
  return schema.parse(input) as T;
}

export function buildTodosSchemaBundle(): TodosSchemaBundle {
  const schemas = buildTodosJsonSchemas(TODOS_SCHEMA_REGISTRY);
  const schemaDigest = sha256TodosValue(schemas);
  if (schemaDigest !== TODOS_SCHEMA_BUNDLE_DIGEST) {
    throw new Error("Canonical Todos runtime schemas diverged from the version-neutral schema foundation");
  }
  return {
    schema: "hasna.todos.schema_bundle.v1",
    contractVersion: TODOS_CONTRACT_VERSION,
    manifestVersion: TODOS_MANIFEST_VERSION,
    schemaDigest,
    invariantRegistryDigest: TODOS_INVARIANT_REGISTRY_DIGEST,
    runtimeValidationRequired: true,
    invariants: TODOS_INVARIANT_REGISTRY,
    schemas,
  };
}
