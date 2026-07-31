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
        mode: "postgres",
        engines: ["json", "postgres"],
        envPrefix: "HASNA_IDENTITIES_"
      }
    });

    expect(parsed.success).toBe(true);
  });

  test("rejects an unknown storage engine", () => {
    const parsed = ServiceContractManifestSchema.safeParse({
      ...baseServiceManifest,
      storage: {
        mode: "postgres",
        engines: ["filesystem", "postgres"],
        envPrefix: "HASNA_IDENTITIES_"
      }
    });

    expect(parsed.success).toBe(false);
  });

  for (const mode of ["sqlite", "postgres"] as const) {
    test(`continues to accept existing ${mode} service manifests`, () => {
      const parsed = ServiceContractManifestSchema.safeParse({
        ...baseServiceManifest,
        storage: {
          mode,
          engines: ["sqlite", "postgres"],
          envPrefix: "HASNA_IDENTITIES_",
          sqlitePath: "~/.hasna/identities/identities.db"
        }
      });

      expect(parsed.success).toBe(true);
    });
  }
});
