import { describe, expect, test } from "bun:test";
import { SCHEMA_IDS, SERVICE_CONTRACT_VERSION, ServiceContractManifestSchema } from "./schemas.js";

const baseServiceManifest = {
  schema: SCHEMA_IDS.serviceContract,
  name: "identities",
  class: "service",
  contractVersion: SERVICE_CONTRACT_VERSION,
  kitVersion: "0.8.2",
  bins: ["identities", "identities-serve"],
  serviceSurfaces: [
    {
      name: "http",
      status: "deferred",
      authMode: "api-key",
      deferReason: "Schema fixture only."
    }
  ]
} as const;

describe("service storage engines", () => {
  test("accepts a JSON-file local store with PostgreSQL support", () => {
    const parsed = ServiceContractManifestSchema.safeParse({
      ...baseServiceManifest,
      storage: {
        backend: "postgresql",
        engines: ["json", "postgresql"],
        envPrefix: "HASNA_IDENTITIES_"
      }
    });

    expect(parsed.success).toBe(true);
  });

  test("rejects an unknown storage engine", () => {
    const parsed = ServiceContractManifestSchema.safeParse({
      ...baseServiceManifest,
      storage: {
        backend: "postgresql",
        engines: ["filesystem", "postgresql"],
        envPrefix: "HASNA_IDENTITIES_"
      }
    });

    expect(parsed.success).toBe(false);
  });

  for (const backend of ["sqlite", "postgresql"] as const) {
    test(`accepts ${backend} service manifests`, () => {
      const parsed = ServiceContractManifestSchema.safeParse({
        ...baseServiceManifest,
        storage: {
          backend,
          engines: ["sqlite", "postgresql"],
          envPrefix: "HASNA_IDENTITIES_",
          sqlitePath: "~/.hasna/identities/identities.db"
        }
      });

      expect(parsed.success).toBe(true);
    });
  }
});
