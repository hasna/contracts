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
  ContractSchemaRegistry,
  SERVICE_SURFACE_KINDS,
  STORAGE_ENGINES,
  HOSTING_MODES
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

  test("exports the portable surface, storage capability, and hosting vocabularies", () => {
    expect(SERVICE_SURFACE_KINDS).toEqual(["api", "sdk", "mcp", "cli"]);
    expect(STORAGE_ENGINES).toEqual(["sqlite", "postgres"]);
    expect(HOSTING_MODES).toEqual(["user-hosted", "hasna-saas"]);
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

  test("normalizes legacy self-hosted placement spelling without conflating it with cloud", () => {
    const parsed = validateServiceContractManifest({
      ...baseCliWithStore,
      deploymentModes: ["local", "self-hosted"]
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.deploymentModes).toEqual(["local", "self_hosted"]);
      expect(parsed.data.deploymentModes).not.toContain("cloud");
    }
  });

  test("defaults the public product story to user-hosted", () => {
    const parsed = validateServiceContractManifest(baseCliWithStore);
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.hosting).toEqual(["user-hosted"]);
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

  test("cloud storage can use the public env contract without a secret reference", () => {
    const publicManifest = {
      ...baseCliWithStore,
      storage: {
        mode: "cloud",
        envPrefix: "HASNA_TODOS_"
      }
    };
    expect(validateServiceContractManifest(publicManifest).success).toBe(true);

    const privateCompatibility = {
      ...baseCliWithStore,
      storage: {
        mode: "cloud",
        envPrefix: "HASNA_TODOS_",
        databaseUrlSecretRef: "hasna/oss/todos/database-url"
      }
    };
    expect(validateServiceContractManifest(privateCompatibility).success).toBe(true);
  });

  test("service class requires a -serve bin and storage", () => {
    const svc = {
      schema: SCHEMA_IDS.serviceContract,
      name: "loops",
      class: "service",
      contractVersion: SERVICE_CONTRACT_VERSION,
      kitVersion: "0.3.0",
      bins: ["loops", "loops-serve"],
      storage: { mode: "cloud", databaseUrlSecretRef: "hasna/oss/loops/database-url" },
      deploymentModes: ["local", "self-hosted"],
      serviceSurfaces: [
        {
          name: "http",
          status: "supported",
          bin: "loops-serve",
          authMode: "api-key",
          deploymentModes: ["local", "self-hosted"],
          health: { method: "GET", path: "/health", public: true },
          readiness: { method: "GET", path: "/ready", public: false },
          version: { method: "GET", path: "/version", public: true },
          apiBasePath: "/v1",
          readinessGates: [
            {
              id: "redaction",
              kind: "redaction",
              status: "pending"
            }
          ]
        }
      ]
    };
    expect(validateServiceContractManifest(svc).success).toBe(true);
    expect(validateServiceContractManifest({ ...svc, bins: ["loops"] }).success).toBe(false);
    expect(validateServiceContractManifest({ ...svc, serviceSurfaces: [] }).success).toBe(false);
  });

  test("supported API surfaces require GET health, readiness, and version endpoints", () => {
    const service = {
      schema: SCHEMA_IDS.serviceContract,
      name: "loops",
      class: "service",
      contractVersion: SERVICE_CONTRACT_VERSION,
      kitVersion: "0.7.0",
      bins: ["loops", "loops-serve"],
      storage: {
        mode: "local",
        engines: ["sqlite", "postgres"],
        envPrefix: "HASNA_LOOPS_",
        sqlitePath: "~/.hasna/loops/loops.db",
        pgTestGate: {
          envVar: "LOOPS_TEST_DATABASE_URL",
          command: "bun test tests/postgres.test.ts"
        }
      },
      serviceSurfaces: [
        {
          name: "http",
          kind: "api",
          status: "supported",
          bin: "loops-serve",
          authMode: "api-key",
          deploymentModes: ["local"],
          health: { method: "POST", path: "/health", public: true },
          version: { method: "POST", path: "/version", public: true },
          apiBasePath: "/v1",
          openApiPath: "/openapi.json"
        }
      ]
    };
    const parsed = validateServiceContractManifest(service);
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      const paths = parsed.error.issues.map((issue) => issue.path.join("."));
      expect(paths).toContain("serviceSurfaces.0.health.method");
      expect(paths).toContain("serviceSurfaces.0.readiness");
      expect(paths).toContain("serviceSurfaces.0.version.method");
    }
  });

  test("saas storage requires the public DATABASE_URL env prefix", () => {
    const saas = {
      schema: SCHEMA_IDS.serviceContract,
      name: "mailery",
      class: "saas",
      contractVersion: SERVICE_CONTRACT_VERSION,
      kitVersion: "0.7.0",
      bins: ["mailery", "mailery-serve"],
      hosting: ["hasna-saas"],
      deploymentModes: ["cloud"],
      storage: { mode: "cloud" },
      serviceSurfaces: [
        {
          name: "http",
          kind: "api",
          status: "supported",
          bin: "mailery-serve",
          authMode: "api-key",
          deploymentModes: ["cloud"],
          health: { method: "GET", path: "/health", public: true },
          readiness: { method: "GET", path: "/ready", public: false },
          version: { method: "GET", path: "/version", public: true },
          apiBasePath: "/v1",
          openApiPath: "/openapi.json"
        }
      ]
    };
    const parsed = validateServiceContractManifest(saas);
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((issue) => issue.path.join(".") === "storage.envPrefix")).toBe(true);
    }
  });

  test("service storage capability declarations require both engines", () => {
    const service = {
      schema: SCHEMA_IDS.serviceContract,
      name: "loops",
      class: "service",
      contractVersion: SERVICE_CONTRACT_VERSION,
      kitVersion: "0.6.0",
      bins: ["loops", "loops-serve"],
      storage: {
        mode: "local",
        engines: ["sqlite"],
        sqlitePath: "~/.hasna/loops/loops.db"
      },
      serviceSurfaces: [
        {
          name: "http",
          status: "deferred",
          authMode: "api-key",
          deploymentModes: ["local"],
          deferReason: "Fixture only."
        }
      ]
    };
    const parsed = validateServiceContractManifest(service);
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((issue) => issue.message.includes("both sqlite and postgres"))).toBe(true);
    }
  });

  test("rejects non-database SQLite paths", () => {
    const bad = {
      ...baseCliWithStore,
      storage: {
        mode: "local",
        sqlitePath: "~/.hasna/todos/accounts.json"
      }
    };
    const parsed = validateServiceContractManifest(bad);
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((issue) => issue.path.join(".") === "storage.sqlitePath")).toBe(true);
    }
  });

  test("rejects duplicate engines, hosting stories, and surface waivers", () => {
    const duplicateEngines = {
      ...baseCliWithStore,
      storage: {
        mode: "local",
        engines: ["sqlite", "sqlite"],
        sqlitePath: "~/.hasna/todos/todos.db"
      }
    };
    expect(validateServiceContractManifest(duplicateEngines).success).toBe(false);
    expect(validateServiceContractManifest({ ...baseCliWithStore, hosting: ["user-hosted", "user-hosted"] }).success).toBe(false);
    expect(
      validateServiceContractManifest({
        ...baseCliWithStore,
        metadata: {
          conformance: {
            waivedSurfaces: [
              { kind: "api", reason: "No HTTP runtime." },
              { kind: "api", reason: "Duplicate waiver." }
            ]
          }
        }
      }).success
    ).toBe(false);
  });

  test("rejects malformed surface waivers", () => {
    const bad = {
      ...baseCliWithStore,
      metadata: {
        conformance: {
          waivedSurfaces: [{ kind: "sdk", reason: "   " }]
        }
      }
    };
    expect(validateServiceContractManifest(bad).success).toBe(false);
  });

  test("types the exceptional non-Node surface waiver profile", () => {
    const eligible = {
      ...baseCliWithStore,
      metadata: {
        conformance: {
          waiverProfile: "non-node-monorepo",
          waivedSurfaces: [{ kind: "sdk", reason: "SDK is provided by the non-Node toolchain." }]
        }
      }
    };
    expect(validateServiceContractManifest(eligible).success).toBe(true);

    const invalid = {
      ...eligible,
      metadata: {
        conformance: {
          waiverProfile: "arbitrary-exception",
          waivedSurfaces: [{ kind: "sdk", reason: "Invalid profile." }]
        }
      }
    };
    expect(validateServiceContractManifest(invalid).success).toBe(false);
  });

  test("preserves legacy conformance metadata while typing surface waivers", () => {
    const legacy = {
      ...baseCliWithStore,
      metadata: {
        conformance: {
          checkCommand: "bun run check:contracts",
          evidencePath: "artifacts/contracts.json"
        }
      }
    };
    const parsed = validateServiceContractManifest(legacy);
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.metadata?.conformance?.checkCommand).toBe("bun run check:contracts");
      expect(parsed.data.metadata?.conformance?.waivedSurfaces).toEqual([]);
    }
  });

  test("service surfaces require lifecycle endpoints or explicit defer reasons", () => {
    const badSupported = {
      ...baseCliWithStore,
      class: "service",
      bins: ["todos", "todos-serve"],
      storage: { mode: "cloud", databaseUrlSecretRef: "hasna/oss/todos/database-url" },
      serviceSurfaces: [
        {
          name: "http",
          status: "supported",
          bin: "todos-serve",
          authMode: "api-key",
          deploymentModes: ["local"]
        }
      ]
    };
    expect(validateServiceContractManifest(badSupported).success).toBe(false);

    const deferred = {
      ...badSupported,
      serviceSurfaces: [
        {
          name: "http",
          status: "deferred",
          authMode: "api-key",
          deploymentModes: ["local"],
          deferReason: "Hosted service boundary still returns raw secret values."
        }
      ]
    };
    expect(validateServiceContractManifest(deferred).success).toBe(true);
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

  test("this repo dogfoods the package version and explicit surface policy", () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as { version: string };
    const loaded = loadServiceContractManifest(repoRoot);
    expect(loaded.ok).toBe(true);
    if (loaded.ok) {
      expect(loaded.manifest.kitVersion).toBe(pkg.version);
      expect(loaded.manifest.hosting).toEqual(["user-hosted"]);
      expect(loaded.manifest.serviceSurfaces.map((surface) => surface.kind)).toEqual(["sdk", "cli"]);
      expect(loaded.manifest.metadata?.conformance?.waivedSurfaces.map((waiver) => waiver.kind)).toEqual(["api", "mcp"]);
    }
  });
});
