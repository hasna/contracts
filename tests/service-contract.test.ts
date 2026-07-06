import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  SCHEMA_IDS,
  ServiceContractManifestSchema,
  SERVICE_CONTRACT_VERSION,
  allowedBinsForName,
  databaseUrlSecretRefFor,
  defaultSqlitePathFor,
  serviceContractSpec,
  validateServiceContractManifest,
  loadServiceContractManifest,
  SERVICE_CONTRACT_JSON_SCHEMA,
  ContractSchemaRegistry
} from "../src";

const repoRoot = join(import.meta.dir, "..");

const baseCliWithStore = {
  schema: SCHEMA_IDS.serviceContract,
  name: "todos",
  class: "cli-with-store",
  contractVersion: SERVICE_CONTRACT_VERSION,
  kitVersion: "0.3.0",
  bins: ["todos", "todos-mcp"],
  storage: {
    mode: "local",
    sqlitePath: "~/.hasna/todos/todos.db"
  }
} as const;

describe("service contract helpers", () => {
  test("allowlist, secret ref, and sqlite path derivation", () => {
    expect(allowedBinsForName("todos")).toContain("todos");
    expect(allowedBinsForName("todos")).toContain("todos-serve");
    expect(allowedBinsForName("todos")).not.toContain("todos-sync");
    expect(databaseUrlSecretRefFor("todos")).toBe("hasna/oss/todos/database-url");
    expect(defaultSqlitePathFor("todos")).toBe("~/.hasna/todos/todos.db");
  });

  test("serviceContractSpec bundles env + refs", () => {
    const spec = serviceContractSpec("mailery");
    expect(spec.env.modeKeys[0]).toBe("HASNA_MAILERY_STORAGE_MODE");
    expect(spec.databaseUrlSecretRef).toBe("hasna/oss/mailery/database-url");
    expect(spec.sqlitePath).toBe("~/.hasna/mailery/mailery.db");
  });

  test("is registered in the schema registry", () => {
    expect(ContractSchemaRegistry[SCHEMA_IDS.serviceContract]).toBe(ServiceContractManifestSchema);
  });
});

describe("service contract manifest validation", () => {
  test("accepts a valid cli-with-store manifest", () => {
    expect(validateServiceContractManifest(baseCliWithStore).success).toBe(true);
  });

  test("rejects bins outside the allowlist", () => {
    const bad = { ...baseCliWithStore, bins: ["todos", "todos-sync"] };
    const r = validateServiceContractManifest(bad);
    expect(r.success).toBe(false);
  });

  test("rejects deprecated mode aliases in the manifest (strict enum)", () => {
    const bad = { ...baseCliWithStore, storage: { mode: "hybrid", sqlitePath: "x" } };
    expect(validateServiceContractManifest(bad).success).toBe(false);
  });

  test("library must not declare storage or serve/mcp bins", () => {
    const lib = {
      schema: SCHEMA_IDS.serviceContract,
      name: "contracts",
      class: "library",
      contractVersion: SERVICE_CONTRACT_VERSION,
      kitVersion: "0.3.0",
      bins: ["contracts", "contracts-cli"]
    };
    expect(validateServiceContractManifest(lib).success).toBe(true);
    expect(validateServiceContractManifest({ ...lib, storage: { mode: "local", sqlitePath: "x" } }).success).toBe(false);
    expect(validateServiceContractManifest({ ...lib, bins: ["contracts", "contracts-serve"] }).success).toBe(false);
  });

  test("cloud storage requires a database secret ref", () => {
    const bad = { ...baseCliWithStore, storage: { mode: "cloud" } };
    expect(validateServiceContractManifest(bad).success).toBe(false);
    const good = { ...baseCliWithStore, storage: { mode: "cloud", databaseUrlSecretRef: "hasna/oss/todos/database-url" } };
    expect(validateServiceContractManifest(good).success).toBe(true);
  });

  test("service class requires a -serve bin and storage", () => {
    const svc = {
      schema: SCHEMA_IDS.serviceContract,
      name: "loops",
      class: "service",
      contractVersion: SERVICE_CONTRACT_VERSION,
      kitVersion: "0.3.0",
      bins: ["loops", "loops-serve"],
      storage: { mode: "cloud", databaseUrlSecretRef: "hasna/oss/loops/database-url" }
    };
    expect(validateServiceContractManifest(svc).success).toBe(true);
    expect(validateServiceContractManifest({ ...svc, bins: ["loops"] }).success).toBe(false);
  });

  test("saas class must be cloud mode", () => {
    const saas = {
      schema: SCHEMA_IDS.serviceContract,
      name: "mailery",
      class: "saas",
      contractVersion: SERVICE_CONTRACT_VERSION,
      kitVersion: "0.3.0",
      bins: ["mailery", "mailery-serve"],
      storage: { mode: "local", sqlitePath: "x" }
    };
    expect(validateServiceContractManifest(saas).success).toBe(false);
  });
});

describe("service contract JSON schema and repo manifest", () => {
  test("shipped JSON schema file matches the exported constant", () => {
    const shipped = JSON.parse(readFileSync(join(repoRoot, "src", "hasna.contract.schema.json"), "utf8"));
    expect(shipped).toEqual(SERVICE_CONTRACT_JSON_SCHEMA);
  });

  test("this repo's hasna.contract.json is a valid library manifest", () => {
    const loaded = loadServiceContractManifest(repoRoot);
    expect(loaded.ok).toBe(true);
    if (loaded.ok) {
      expect(loaded.manifest.name).toBe("contracts");
      expect(loaded.manifest.class).toBe("library");
    }
  });
});
