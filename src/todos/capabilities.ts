import {
  TODOS_MANIFEST_VERSION,
  sha256TodosValue,
} from "./common";
import {
  TODOS_CAPABILITY_SCHEMA_IDS,
  TodosCapabilityManifestSchema,
  TodosCapabilitySchema,
  type TodosCapability,
  type TodosCapabilityManifest,
} from "./capability-schema";
import {
  TODOS_CAPABILITY_IDS,
  TODOS_OPERATION_MANIFEST,
  type TodosCapabilityId,
  type TodosOperation,
  type TodosOperationManifest,
} from "./operations";

function operationsForCapability(
  capabilityId: TodosCapabilityId,
  operations: readonly TodosOperation[],
): TodosOperation[] {
  switch (capabilityId) {
    case "cursor-pagination":
      return operations.filter((operation) => operation.pagination === "cursor");
    case "idempotency":
      return operations.filter((operation) => operation.idempotency !== "none");
    case "optimistic-concurrency":
      return operations.filter((operation) => operation.concurrency === "version");
    case "typed-errors":
      return [...operations];
    default:
      return operations.filter((operation) => operation.capabilityId === capabilityId);
  }
}

function orderedModes(operations: readonly TodosOperation[]): Array<"local" | "cloud"> {
  const modes = new Set(operations.flatMap((operation) => operation.supportedModes));
  return (["local", "cloud"] as const).filter((mode) => modes.has(mode));
}

function orderedAudiences(operations: readonly TodosOperation[]): Array<"customer" | "tenant_admin"> {
  const audiences = new Set(operations.map((operation) => operation.audience));
  return (["customer", "tenant_admin"] as const).filter((audience) => audiences.has(audience));
}

export function deriveTodosCapabilities(
  manifest: TodosOperationManifest = TODOS_OPERATION_MANIFEST,
): TodosCapability[] {
  const capabilities = TODOS_CAPABILITY_IDS.map((capabilityId) => {
    const operations = operationsForCapability(capabilityId, manifest.operations);
    if (operations.length === 0) {
      throw new Error(`Capability has no deriving operations: ${capabilityId}`);
    }
    const primaryOperations = manifest.operations.filter(
      (operation) => operation.capabilityId === capabilityId,
    );
    return TodosCapabilitySchema.parse({
      id: capabilityId,
      availability: primaryOperations.length > 0
        && primaryOperations.every((operation) => operation.availability === "gated")
        ? "gated"
        : "core",
      operationIds: operations.map((operation) => operation.id).sort((left, right) => left.localeCompare(right)),
      modes: orderedModes(operations),
      audiences: orderedAudiences(operations),
    });
  });
  return capabilities.sort((left, right) => left.id.localeCompare(right.id));
}

export function createTodosCapabilityManifest(
  manifest: TodosOperationManifest = TODOS_OPERATION_MANIFEST,
): TodosCapabilityManifest {
  return TodosCapabilityManifestSchema.parse({
    schema: TODOS_CAPABILITY_SCHEMA_IDS.manifest,
    version: TODOS_MANIFEST_VERSION,
    manifestDigest: sha256TodosValue(manifest),
    capabilities: deriveTodosCapabilities(manifest),
  });
}

export const TODOS_CAPABILITY_MANIFEST = createTodosCapabilityManifest();
