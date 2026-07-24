import {
  sha256TodosValue,
} from "./common";
import {
  TODOS_CAPABILITY_MANIFEST,
} from "./capabilities";
import {
  TODOS_CONTRACT_SCHEMA_ID,
  TODOS_CONTRACT_SCHEMAS,
  TodosContractDescriptorSchema,
  type TodosContractDescriptor,
} from "./contract-schema";
import {
  TODOS_GENERATOR_IDENTITY_DIGEST,
} from "./generator-provenance";
import {
  TODOS_INVARIANT_REGISTRY_DIGEST,
} from "./invariants";
import {
  TODOS_OPERATION_MANIFEST,
  TODOS_OPERATION_MANIFEST_DIGEST,
} from "./operations";
import {
  TODOS_CONTRACT_NAMESPACE,
  TODOS_CONTRACT_VERSION,
  TODOS_MANIFEST_VERSION,
} from "./common";
import {
  TODOS_CONTRACT_PROVENANCE,
  TODOS_PROVENANCE_DIGEST,
} from "./provenance";
import {
  TODOS_SCHEMA_BUNDLE_DIGEST,
} from "./schema-foundation";

export const TODOS_CONTRACT_DESCRIPTOR: TodosContractDescriptor = TodosContractDescriptorSchema.parse({
  schema: TODOS_CONTRACT_SCHEMA_ID,
  namespace: TODOS_CONTRACT_NAMESPACE,
  contractVersion: TODOS_CONTRACT_VERSION,
  manifestVersion: TODOS_MANIFEST_VERSION,
  manifestDigest: TODOS_OPERATION_MANIFEST_DIGEST,
  capabilityManifestDigest: sha256TodosValue(TODOS_CAPABILITY_MANIFEST),
  schemaBundleDigest: TODOS_SCHEMA_BUNDLE_DIGEST,
  invariantRegistryDigest: TODOS_INVARIANT_REGISTRY_DIGEST,
  provenanceDigest: TODOS_PROVENANCE_DIGEST,
  generatorIdentityDigest: TODOS_GENERATOR_IDENTITY_DIGEST,
  publicSubpath: "@hasna/contracts/todos",
  rootExported: false,
  authorityInvariant: {
    count: 1,
  },
  provenance: TODOS_CONTRACT_PROVENANCE,
});

export const TODOS_CONTRACT_DIGEST = sha256TodosValue(TODOS_CONTRACT_DESCRIPTOR);

// @todos-runtime-validator contract.verify_digest_closure
export function verifyTodosContractDigests(): boolean {
  return TODOS_CONTRACT_DESCRIPTOR.manifestDigest === sha256TodosValue(TODOS_OPERATION_MANIFEST)
    && TODOS_CONTRACT_DESCRIPTOR.capabilityManifestDigest === sha256TodosValue(TODOS_CAPABILITY_MANIFEST)
    && TODOS_CONTRACT_DESCRIPTOR.schemaBundleDigest === TODOS_SCHEMA_BUNDLE_DIGEST
    && TODOS_CONTRACT_DESCRIPTOR.invariantRegistryDigest === TODOS_INVARIANT_REGISTRY_DIGEST
    && TODOS_CONTRACT_DESCRIPTOR.provenanceDigest === TODOS_PROVENANCE_DIGEST
    && TODOS_CONTRACT_DESCRIPTOR.generatorIdentityDigest === TODOS_GENERATOR_IDENTITY_DIGEST
    && TODOS_CONTRACT_DIGEST === sha256TodosValue(TODOS_CONTRACT_DESCRIPTOR);
}

// @todos-runtime-validator contract.digest_closure
export function validateTodosContractDescriptor(input: unknown): input is TodosContractDescriptor {
  const parsed = TodosContractDescriptorSchema.safeParse(input);
  return parsed.success
    && sha256TodosValue(parsed.data) === TODOS_CONTRACT_DIGEST
    && parsed.data.manifestDigest === TODOS_OPERATION_MANIFEST_DIGEST
    && parsed.data.capabilityManifestDigest === sha256TodosValue(TODOS_CAPABILITY_MANIFEST)
    && parsed.data.schemaBundleDigest === TODOS_SCHEMA_BUNDLE_DIGEST
    && parsed.data.invariantRegistryDigest === TODOS_INVARIANT_REGISTRY_DIGEST
    && parsed.data.provenanceDigest === TODOS_PROVENANCE_DIGEST
    && parsed.data.generatorIdentityDigest === TODOS_GENERATOR_IDENTITY_DIGEST;
}

export {
  TODOS_CONTRACT_SCHEMA_ID,
  TODOS_CONTRACT_SCHEMAS,
  TodosContractDescriptorSchema,
};
export type {
  TodosContractDescriptor,
};
