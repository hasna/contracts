import {
  TODOS_MANIFEST_VERSION,
  sha256TodosValue,
} from "./common";
import {
  TODOS_CAPABILITY_MANIFEST,
} from "./capabilities";
import {
  TODOS_INVARIANT_REGISTRY_DIGEST,
} from "./invariants";
import {
  TODOS_OPERATION_MANIFEST_DIGEST,
} from "./operations";
import {
  TODOS_PROVENANCE_DIGEST,
  TODOS_SOURCE_FREEZE,
} from "./provenance";
import {
  TODOS_SCHEMA_BUNDLE_DIGEST,
} from "./schema-foundation";

export const TODOS_GENERATOR_VERSION = "1.0.0" as const;
export const TODOS_GENERATOR_PROVENANCE_SCHEMA_ID =
  "hasna.todos.generator_provenance.v1" as const;

export const TODOS_GENERATOR_IDENTITY = Object.freeze({
  schema: TODOS_GENERATOR_PROVENANCE_SCHEMA_ID,
  generatorVersion: TODOS_GENERATOR_VERSION,
  sourceFreeze: TODOS_SOURCE_FREEZE,
  sourceModules: Object.freeze([
    {
      module: "src/todos/operations.ts",
      contentDigest: TODOS_OPERATION_MANIFEST_DIGEST,
    },
    {
      module: "src/todos/capabilities.ts",
      contentDigest: sha256TodosValue(TODOS_CAPABILITY_MANIFEST),
    },
    {
      module: "src/todos/schema-foundation.ts",
      contentDigest: TODOS_SCHEMA_BUNDLE_DIGEST,
    },
    {
      module: "src/todos/invariants.ts",
      contentDigest: TODOS_INVARIANT_REGISTRY_DIGEST,
    },
    {
      module: "src/todos/provenance.ts",
      contentDigest: TODOS_PROVENANCE_DIGEST,
    },
  ]),
  manifestVersion: TODOS_MANIFEST_VERSION,
});

export const TODOS_GENERATOR_IDENTITY_DIGEST = sha256TodosValue(TODOS_GENERATOR_IDENTITY);

export function buildTodosGeneratorProvenance(
  contractDigest: string,
): Record<string, unknown> {
  return {
    ...TODOS_GENERATOR_IDENTITY,
    identityDigest: TODOS_GENERATOR_IDENTITY_DIGEST,
    outputContractDigest: contractDigest,
  };
}
