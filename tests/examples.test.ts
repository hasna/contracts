import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { ContractSchemaRegistry, SCHEMA_IDS, type KnownSchemaId, validateContract } from "../src";

const examplesDir = join(import.meta.dir, "..", "examples");
const expectedInvalidIssuePaths: Record<string, string[]> = {
  "announcement.invalid.json": ["audienceRef.kind"],
  "app.invalid.json": ["surfaces.bins.1"],
  "app-cloud-manifest.invalid.json": ["cloudResources.0.ownerPackage", "dependencies", "forbiddenSharedRuntimes", "packageName"],
  "audience.invalid.json": ["definition.predicates.0.key"],
  "integration-ref.invalid.json": ["uri"],
  "release.invalid.json": ["evidenceRefs"],
  "rollout-record.invalid.json": ["result"],
  "no-cloud-evidence-pack.invalid.json": ["checks", "checks", "findings"],
  "project-manifest.invalid.json": ["slug"],
  "project-panel.invalid.json": ["stateReason"],
  "project-snapshot.invalid.json": ["panels.0.projectId"],
  "proof-bundle.invalid.json": ["checks", "evidenceRefs", "verifier"],
  "render-manifest.invalid.json": ["views"],
  "resource-ref.invalid.json": ["uri"],
  "scaffold-install-record.invalid.json": ["generatedFiles", "installedAt"],
  "scaffold-manifest.invalid.json": ["output", "validationChecks"],
  "service-contract.invalid.json": ["bins.1"],
  "validation-plan.invalid.json": ["checks.0.command"]
};

function exampleFiles() {
  return readdirSync(examplesDir)
    .filter((file) => file.endsWith(".valid.json") || file.endsWith(".invalid.json"))
    .sort();
}

function readExample(file: string) {
  return JSON.parse(readFileSync(join(examplesDir, file), "utf8"));
}

function embeddedSchema(value: unknown): KnownSchemaId | null {
  if (!value || typeof value !== "object" || !("schema" in value)) {
    return null;
  }
  const schema = (value as { schema?: unknown }).schema;
  return typeof schema === "string" && schema in ContractSchemaRegistry ? (schema as KnownSchemaId) : null;
}

describe("example fixtures", () => {
  test("ships a valid example for every known schema", () => {
    const validSchemas = new Set<KnownSchemaId>();
    for (const file of exampleFiles().filter((entry) => entry.endsWith(".valid.json"))) {
      const schemaId = embeddedSchema(readExample(file));
      expect(schemaId).not.toBeNull();
      if (schemaId) {
        validSchemas.add(schemaId);
      }
    }

    expect([...validSchemas].sort()).toEqual(Object.values(SCHEMA_IDS).sort());
  });

  test("valid and invalid examples match their filename contract", () => {
    for (const file of exampleFiles()) {
      const value = readExample(file);
      const schemaId = embeddedSchema(value);
      expect(schemaId).not.toBeNull();

      const result = validateContract(schemaId as KnownSchemaId, value);
      if (file.endsWith(".valid.json")) {
        expect(result.success).toBe(true);
      } else {
        expect(result.success).toBe(false);
        if (!result.success) {
          const issuePaths = result.error.issues.map((issue) => issue.path.join("."));
          expect(issuePaths.sort()).toEqual((expectedInvalidIssuePaths[file] ?? []).sort());
        }
      }
    }
  });
});
