import {
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = join(import.meta.dir, "..");
const temporaryDirectory = mkdtempSync(join(tmpdir(), "contracts-todos-pack-"));

function text(value: Uint8Array): string {
  return new TextDecoder().decode(value);
}

try {
  const packed = Bun.spawnSync(
    ["bun", "pm", "pack", "--destination", temporaryDirectory, "--ignore-scripts"],
    {
      cwd: root,
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  if (packed.exitCode !== 0) {
    throw new Error(`pack failed\n${text(packed.stdout)}\n${text(packed.stderr)}`);
  }
  const archiveName = readdirSync(temporaryDirectory).find((entry) => entry.endsWith(".tgz"));
  if (!archiveName) {
    throw new Error("pack did not produce an archive");
  }
  const archivePath = join(temporaryDirectory, archiveName);
  const listing = Bun.spawnSync(["tar", "-tzf", archivePath], {
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (listing.exitCode !== 0) {
    throw new Error(`archive listing failed\n${text(listing.stderr)}`);
  }
  const entries = new Set(text(listing.stdout).split("\n").filter(Boolean));
  for (const required of [
    "package/dist/todos/index.js",
    "package/dist/todos/index.d.ts",
    "package/generated/todos/v1/contract.json",
    "package/generated/todos/v1/operation-manifest.json",
    "package/generated/todos/v1/invariant-registry.json",
    "package/generated/todos/v1/generator-provenance.json",
    "package/generated/todos/v1/checksums.json",
  ]) {
    if (!entries.has(required)) {
      throw new Error(`packed archive is missing ${required}`);
    }
  }
  for (const entry of entries) {
    if (entry.startsWith("package/src/todos/")) {
      throw new Error(`packed archive leaked Todos source: ${entry}`);
    }
  }

  const rootPackage = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
    dependencies?: Record<string, string>;
  };
  const zodVersion = rootPackage.dependencies?.zod;
  if (!zodVersion) {
    throw new Error("root package does not declare the Zod runtime dependency");
  }

  const consumerRoot = join(temporaryDirectory, "consumer");
  mkdirSync(consumerRoot);
  writeFileSync(
    join(consumerRoot, "package.json"),
    JSON.stringify({
      name: "@hasna/contracts-todos-isolated-consumer",
      private: true,
      type: "module",
      dependencies: {
        "@hasna/contracts": `file:${archivePath}`,
        zod: zodVersion,
      },
    }, null, 2),
    "utf8",
  );
  const install = Bun.spawnSync(["bun", "install", "--ignore-scripts"], {
    cwd: consumerRoot,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (install.exitCode !== 0) {
    throw new Error(`isolated consumer install failed\n${text(install.stdout)}\n${text(install.stderr)}`);
  }

  const packageRoot = join(consumerRoot, "node_modules", "@hasna", "contracts");
  if (lstatSync(packageRoot).isSymbolicLink()) {
    throw new Error("isolated consumer resolved @hasna/contracts through a symlink");
  }
  const packageJson = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")) as {
    exports?: Record<string, unknown>;
  };
  if (!packageJson.exports?.["./todos"] || !packageJson.exports?.["./todos/artifacts/*"]) {
    throw new Error("packed package is missing Todos export mappings");
  }
  const todosExportKeys = Object.keys(packageJson.exports)
    .filter((key) => key.startsWith("./todos"))
    .sort();
  if (
    JSON.stringify(todosExportKeys)
    !== JSON.stringify(["./todos", "./todos/artifacts/*"])
  ) {
    throw new Error(`packed package exposes unexpected Todos subpaths: ${todosExportKeys.join(", ")}`);
  }

  writeFileSync(
    join(consumerRoot, "smoke.mjs"),
    `import * as root from "@hasna/contracts";
import * as todos from "@hasna/contracts/todos";
import contract from "@hasna/contracts/todos/artifacts/contract.json" with { type: "json" };
import invariants from "@hasna/contracts/todos/artifacts/invariant-registry.json" with { type: "json" };
import { z } from "zod";

if ("TodosModeSchema" in root) throw new Error("Todos leaked through the package root");
if (todos.TodosModeSchema.parse("local") !== "local") throw new Error("Todos subpath did not load");
if (todos.TodosModeSchema.safeParse("remote").success) throw new Error("Todos mode validation drifted");
if ("createTodosTransferBundleWithDigests" in todos) throw new Error("structural transfer builder leaked publicly");
for (const internalName of [
  "TODOS_SCHEMA_FOUNDATION_REGISTRY",
  "TODOS_SCHEMA_FOUNDATION",
  "TODOS_SCHEMA_BUNDLE_DIGEST",
  "buildTodosJsonSchemas",
  "TODOS_SCHEMA_REGISTRY",
  "getTodosSchema",
  "parseTodosSchema",
  "buildTodosSchemaBundle",
  "TodosTransferCheckpointStructuralSchema",
  "TodosMigrationReceiptStructuralSchema",
  "createTodosTransferCheckpointIntegrity",
  "createTodosMigrationReceiptIntegrity",
  "validateTodosMigrationReceiptChainIntegrity",
  "validateTodosTransferCheckpointTransitionIntegrity",
]) {
  if (internalName in todos) throw new Error(\`internal transfer boundary leaked publicly: \${internalName}\`);
}
const historicalBinding = {
  sourceAuthorityId: "tenant-a",
  targetAuthorityId: "tenant-a-cloud",
  bundleId: "bundle-historical",
  bundleChecksum: "1".repeat(64),
  contractDigest: "0".repeat(64),
  manifestDigest: todos.TODOS_OPERATION_MANIFEST_DIGEST,
};
const historicalCheckpointInput = {
  ...historicalBinding,
  importPlanId: todos.computeTodosImportPlanId(historicalBinding),
  importPlanDigest: "2".repeat(64),
  idempotencyKey: "historical-key",
  sequence: 0,
  completedSections: [],
  nextSection: "projects",
  state: "pending",
};
const historicalCheckpointUnsigned = {
  schema: todos.TODOS_TRANSFER_SCHEMA_IDS.checkpoint,
  ...historicalCheckpointInput,
};
const historicalCheckpoint = {
  ...historicalCheckpointUnsigned,
  digest: todos.sha256TodosValue(historicalCheckpointUnsigned),
};
const historicalTerminalUnsigned = {
  schema: todos.TODOS_TRANSFER_SCHEMA_IDS.checkpoint,
  ...historicalBinding,
  importPlanId: todos.computeTodosImportPlanId(historicalBinding),
  importPlanDigest: "2".repeat(64),
  idempotencyKey: "historical-key",
  sequence: todos.TODOS_TRANSFER_SECTION_NAMES.length,
  completedSections: [...todos.TODOS_TRANSFER_SECTION_NAMES],
  nextSection: null,
  state: "committed",
};
const historicalTerminal = {
  ...historicalTerminalUnsigned,
  digest: todos.sha256TodosValue(historicalTerminalUnsigned),
};
const historicalReceiptInput = {
  id: "receipt-historical",
  receiptSequence: 1,
  previousReceiptDigest: null,
  ...historicalBinding,
  importPlanId: todos.computeTodosImportPlanId(historicalBinding),
  importPlanDigest: "2".repeat(64),
  idempotencyKey: "historical-key",
  importedCounts: Object.fromEntries(
    todos.TODOS_TRANSFER_SECTION_NAMES.map((name) => [name, 0]),
  ),
  checkpoint: historicalTerminal,
  committedAt: "2026-07-24T02:00:00.000Z",
};
const historicalReceiptUnsigned = {
  schema: todos.TODOS_TRANSFER_SCHEMA_IDS.migrationReceipt,
  ...historicalReceiptInput,
  status: "committed",
};
const historicalReceipt = {
  ...historicalReceiptUnsigned,
  receiptDigest: todos.sha256TodosValue(historicalReceiptUnsigned),
};
if (todos.TodosTransferCheckpointSchema.safeParse(historicalCheckpoint).success) {
  throw new Error("packed public checkpoint schema accepted a historical digest");
}
if (todos.TODOS_TRANSFER_SCHEMAS[todos.TODOS_TRANSFER_SCHEMA_IDS.checkpoint].safeParse(historicalCheckpoint).success) {
  throw new Error("packed public transfer schema map exposed a structural checkpoint validator");
}
let historicalCheckpointCreated = false;
try {
  todos.createTodosTransferCheckpoint(historicalCheckpointInput);
  historicalCheckpointCreated = true;
} catch {}
if (historicalCheckpointCreated) throw new Error("packed public checkpoint helper accepted a historical digest");
if (todos.validateTodosTransferCheckpointTransition(historicalCheckpoint, historicalTerminal)) {
  throw new Error("packed public checkpoint transition accepted historical digests");
}
if (todos.TodosMigrationReceiptSchema.safeParse(historicalReceipt).success) {
  throw new Error("packed public receipt schema accepted a historical digest");
}
if (todos.TODOS_TRANSFER_SCHEMAS[todos.TODOS_TRANSFER_SCHEMA_IDS.migrationReceipt].safeParse(historicalReceipt).success) {
  throw new Error("packed public transfer schema map exposed a structural receipt validator");
}
let historicalReceiptCreated = false;
try {
  todos.createTodosMigrationReceipt(historicalReceiptInput);
  historicalReceiptCreated = true;
} catch {}
if (historicalReceiptCreated) throw new Error("packed public receipt helper accepted a historical digest");
if (todos.validateTodosMigrationReceiptChain([historicalReceipt]).success) {
  throw new Error("packed public receipt chain accepted a historical digest");
}
if (todos.TodosTransferExecutionContextSchema.safeParse({ state: "committed", receipt: historicalReceipt }).success) {
  throw new Error("packed public execution context accepted a historical receipt");
}
const publicOperationBoundaryIds = todos.TODOS_OPERATION_MANIFEST.operations.flatMap((operation) => {
  if (operation.resource === "transfer" && operation.action === "import_execute") {
    return [operation.requestSchemaId, operation.responseSchemaId];
  }
  if (operation.resource === "migration_receipts") {
    return [operation.responseSchemaId];
  }
  return [];
});
const uniquePublicOperationBoundaryIds = [...new Set(publicOperationBoundaryIds)].sort();
const expectedPublicOperationBoundaryIds = [
  todos.TODOS_REQUEST_SCHEMA_IDS.transferImportExecute,
  todos.TODOS_RESPONSE_SCHEMA_IDS.migrationReceipt,
  todos.TODOS_RESPONSE_SCHEMA_IDS.migrationReceiptPage,
].sort();
if (
  JSON.stringify(uniquePublicOperationBoundaryIds)
  !== JSON.stringify(expectedPublicOperationBoundaryIds)
) {
  throw new Error("packed public transfer operation map inventory drifted");
}
const canonicalMapBundle = todos.createTodosTransferBundle({
  bundleId: "bundle-public-operation-map",
  createdAt: "2026-07-24T02:00:00.000Z",
  source: {
    authorityId: "tenant-a",
    mode: "local",
  },
  records: Object.fromEntries(
    todos.TODOS_TRANSFER_SECTION_NAMES.map((name) => [name, []]),
  ),
});
function mapBundleWithHistoricalDigest(field) {
  const changed = {
    ...canonicalMapBundle,
    [field]: field === "contractDigest" ? "0".repeat(64) : "3".repeat(64),
  };
  const { bundleChecksum: _bundleChecksum, ...unsigned } = changed;
  return {
    ...changed,
    bundleChecksum: todos.computeTodosTransferBundleChecksum(unsigned),
  };
}
function mapExecuteRequest(bundle) {
  const targetAuthorityId = "tenant-a-cloud";
  const importPlanId = todos.computeTodosImportPlanId({
    sourceAuthorityId: bundle.source.authorityId,
    targetAuthorityId,
    bundleId: bundle.bundleId,
    bundleChecksum: bundle.bundleChecksum,
    contractDigest: bundle.contractDigest,
    manifestDigest: bundle.manifestDigest,
  });
  const importPlanDigest = "2".repeat(64);
  const checkpointUnsigned = {
    schema: todos.TODOS_TRANSFER_SCHEMA_IDS.checkpoint,
    sourceAuthorityId: bundle.source.authorityId,
    targetAuthorityId,
    bundleId: bundle.bundleId,
    bundleChecksum: bundle.bundleChecksum,
    contractDigest: bundle.contractDigest,
    manifestDigest: bundle.manifestDigest,
    importPlanId,
    importPlanDigest,
    idempotencyKey: "public-operation-map-key",
    sequence: 0,
    completedSections: [],
    nextSection: "projects",
    state: "pending",
  };
  return {
    bundle,
    targetAuthorityId,
    importPlanId,
    importPlanDigest,
    checkpoint: {
      ...checkpointUnsigned,
      digest: todos.sha256TodosValue(checkpointUnsigned),
    },
  };
}
function mapReceiptWithHistoricalDigest(field) {
  const binding = {
    sourceAuthorityId: "tenant-a",
    targetAuthorityId: "tenant-a-cloud",
    bundleId: "bundle-historical-map",
    bundleChecksum: "1".repeat(64),
    contractDigest: field === "contractDigest"
      ? "0".repeat(64)
      : todos.TODOS_CONTRACT_DIGEST,
    manifestDigest: field === "manifestDigest"
      ? "3".repeat(64)
      : todos.TODOS_OPERATION_MANIFEST_DIGEST,
  };
  const importBinding = {
    ...binding,
    importPlanId: todos.computeTodosImportPlanId(binding),
    importPlanDigest: "2".repeat(64),
    idempotencyKey: "historical-map-key",
  };
  const checkpointUnsigned = {
    schema: todos.TODOS_TRANSFER_SCHEMA_IDS.checkpoint,
    ...importBinding,
    sequence: todos.TODOS_TRANSFER_SECTION_NAMES.length,
    completedSections: [...todos.TODOS_TRANSFER_SECTION_NAMES],
    nextSection: null,
    state: "committed",
  };
  const checkpoint = {
    ...checkpointUnsigned,
    digest: todos.sha256TodosValue(checkpointUnsigned),
  };
  const receiptUnsigned = {
    schema: todos.TODOS_TRANSFER_SCHEMA_IDS.migrationReceipt,
    id: "receipt-historical-map",
    receiptSequence: 1,
    previousReceiptDigest: null,
    ...importBinding,
    status: "committed",
    importedCounts: Object.fromEntries(
      todos.TODOS_TRANSFER_SECTION_NAMES.map((name) => [name, 0]),
    ),
    checkpoint,
    committedAt: "2026-07-24T02:00:00.000Z",
  };
  return {
    ...receiptUnsigned,
    receiptDigest: todos.sha256TodosValue(receiptUnsigned),
  };
}
const publicExecuteRequestSchema = todos.TODOS_REQUEST_SCHEMAS[
  todos.TODOS_REQUEST_SCHEMA_IDS.transferImportExecute
];
const publicReceiptResponseSchema = todos.TODOS_RESPONSE_SCHEMAS[
  todos.TODOS_RESPONSE_SCHEMA_IDS.migrationReceipt
];
const publicReceiptPageResponseSchema = todos.TODOS_RESPONSE_SCHEMAS[
  todos.TODOS_RESPONSE_SCHEMA_IDS.migrationReceiptPage
];
if (!publicExecuteRequestSchema.safeParse(mapExecuteRequest(canonicalMapBundle)).success) {
  throw new Error("packed public transferImportExecute map rejected canonical digests");
}
const canonicalMapReceipt = mapReceiptWithHistoricalDigest("canonical");
if (!publicReceiptResponseSchema.safeParse({
  ok: true,
  data: canonicalMapReceipt,
  requestId: "request-map-1",
}).success) {
  throw new Error("packed public migrationReceipt map rejected canonical digests");
}
if (!publicReceiptPageResponseSchema.safeParse({
  ok: true,
  data: {
    items: [canonicalMapReceipt],
    count: 1,
    nextCursor: null,
  },
  requestId: "request-map-1",
}).success) {
  throw new Error("packed public migrationReceiptPage map rejected canonical digests");
}
for (const field of ["contractDigest", "manifestDigest"]) {
  const mapBundle = mapBundleWithHistoricalDigest(field);
  if (publicExecuteRequestSchema.safeParse(mapExecuteRequest(mapBundle)).success) {
    throw new Error("packed public transferImportExecute map accepted historical " + field);
  }
  const mapReceipt = mapReceiptWithHistoricalDigest(field);
  if (publicReceiptResponseSchema.safeParse({
    ok: true,
    data: mapReceipt,
    requestId: "request-map-1",
  }).success) {
    throw new Error("packed public migrationReceipt map accepted historical " + field);
  }
  if (publicReceiptPageResponseSchema.safeParse({
    ok: true,
    data: {
      items: [mapReceipt],
      count: 1,
      nextCursor: null,
    },
    requestId: "request-map-1",
  }).success) {
    throw new Error("packed public migrationReceiptPage map accepted historical " + field);
  }
}
for (const structuralSubpath of [
  "@hasna/contracts/todos/operation-schemas",
  "@hasna/contracts/todos/public-operation-schemas",
  "@hasna/contracts/todos/schema-foundation",
  "@hasna/contracts/todos/schema-registry",
]) {
  let reachable = false;
  try {
    await import(structuralSubpath);
    reachable = true;
  } catch {}
  if (reachable) throw new Error(\`packed structural subpath is reachable: \${structuralSubpath}\`);
}
if (todos.TodosTransferExecutionContextSchema.safeParse("uncommitted").success) throw new Error("transfer context did not fail closed");
if (contract.digest !== todos.TODOS_CONTRACT_DIGEST) throw new Error("contract artifact digest mismatch");
if (invariants.runtimeValidationRequired !== true) throw new Error("invariant registry is incomplete");
if (typeof z.strictObject !== "function") throw new Error("consumer Zod dependency did not load");
console.log("isolated Todos consumer passed");
`,
    "utf8",
  );
  const smoke = Bun.spawnSync(["bun", "smoke.mjs"], {
    cwd: consumerRoot,
    env: {
      ...process.env,
      NODE_PATH: "",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  if (smoke.exitCode !== 0) {
    throw new Error(`isolated consumer import failed\n${text(smoke.stdout)}\n${text(smoke.stderr)}`);
  }
  console.log(text(smoke.stdout).trim());
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}
