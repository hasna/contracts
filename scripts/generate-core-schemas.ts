import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  CORE_SCHEMA_IDS,
  CORE_SCHEMA_REGISTRY,
  type CoreSchemaId,
} from "../src/primitives.js";

const root = join(import.meta.dir, "..");
const outputDirectory = join(root, "schemas", "v1");
const check = process.argv.includes("--check");

const fileNames: Readonly<Record<CoreSchemaId, string>> = Object.freeze({
  [CORE_SCHEMA_IDS.error]: "error.json",
  [CORE_SCHEMA_IDS.principal]: "principal.json",
  [CORE_SCHEMA_IDS.tenantContext]: "tenant-context.json",
  [CORE_SCHEMA_IDS.idempotency]: "idempotency.json",
  [CORE_SCHEMA_IDS.eventEnvelope]: "event-envelope.json",
  [CORE_SCHEMA_IDS.blobRef]: "blob-ref.json",
  [CORE_SCHEMA_IDS.secretRef]: "secret-ref.json",
  [CORE_SCHEMA_IDS.compatibility]: "compatibility.json",
  [CORE_SCHEMA_IDS.operationDescriptor]: "operation-descriptor.json",
  [CORE_SCHEMA_IDS.capabilityDescriptor]: "capability-descriptor.json",
});

function json(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function renderSchema(schemaId: CoreSchemaId): Record<string, unknown> {
  const generated = zodToJsonSchema(CORE_SCHEMA_REGISTRY[schemaId], {
    $refStrategy: "none",
    target: "jsonSchema7",
    errorMessages: true,
  }) as Record<string, unknown>;
  return {
    $schema: "http://json-schema.org/draft-07/schema#",
    $id: schemaId,
    ...generated,
    "x-hasna-runtime-validator": "validateCoreContract",
  };
}

const rendered = Object.fromEntries(
  Object.values(CORE_SCHEMA_IDS).map((schemaId) => [schemaId, renderSchema(schemaId)]),
) as Record<CoreSchemaId, Record<string, unknown>>;

const files: Record<string, string> = Object.fromEntries(
  Object.entries(fileNames).map(([schemaId, fileName]) => [
    fileName,
    json(rendered[schemaId as CoreSchemaId]),
  ]),
);
files["bundle.json"] = json({
  $schema: "http://json-schema.org/draft-07/schema#",
  $id: "hasna.contracts.schema_bundle.v1",
  release: "1.0.0-rc.1",
  schemas: rendered,
});

const stale: string[] = [];
for (const [fileName, contents] of Object.entries(files)) {
  const target = join(outputDirectory, fileName);
  if (check) {
    try {
      if (readFileSync(target, "utf8") !== contents) stale.push(fileName);
    } catch {
      stale.push(fileName);
    }
  } else {
    mkdirSync(outputDirectory, { recursive: true });
    await Bun.write(target, contents);
  }
}

if (stale.length > 0) {
  console.error(`Core JSON Schemas are stale: ${stale.join(", ")}`);
  process.exit(1);
}

console.log(check ? "Core JSON Schemas are current" : `Wrote ${Object.keys(files).length} core JSON Schemas`);
