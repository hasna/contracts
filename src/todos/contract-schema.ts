import * as z from "zod/v4";
import {
  TODOS_CONTRACT_NAMESPACE,
  TODOS_CONTRACT_VERSION,
  TODOS_MANIFEST_VERSION,
  TodosSha256DigestSchema,
} from "./common";
import {
  TodosContractProvenanceSchema,
} from "./provenance";

export const TODOS_CONTRACT_SCHEMA_ID = "hasna.todos.contract.v1" as const;

export const TodosContractDescriptorSchema = z.strictObject({
  schema: z.literal(TODOS_CONTRACT_SCHEMA_ID),
  namespace: z.literal(TODOS_CONTRACT_NAMESPACE),
  contractVersion: z.literal(TODOS_CONTRACT_VERSION),
  manifestVersion: z.literal(TODOS_MANIFEST_VERSION),
  manifestDigest: TodosSha256DigestSchema,
  capabilityManifestDigest: TodosSha256DigestSchema,
  schemaBundleDigest: TodosSha256DigestSchema,
  invariantRegistryDigest: TodosSha256DigestSchema,
  provenanceDigest: TodosSha256DigestSchema,
  generatorIdentityDigest: TodosSha256DigestSchema,
  publicSubpath: z.literal("@hasna/contracts/todos"),
  rootExported: z.literal(false),
  authorityInvariant: z.strictObject({
    count: z.literal(1),
  }),
  provenance: TodosContractProvenanceSchema,
});
export type TodosContractDescriptor = z.infer<typeof TodosContractDescriptorSchema>;

export const TODOS_CONTRACT_SCHEMAS = Object.freeze({
  [TODOS_CONTRACT_SCHEMA_ID]: TodosContractDescriptorSchema,
});
