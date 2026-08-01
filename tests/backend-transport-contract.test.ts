import { describe, expect, test } from "bun:test";
import { renderKit } from "../src/kit/generate";
import * as contracts from "../src";

const api = contracts as Record<string, unknown>;

function requiredFunction(name: string): (...args: any[]) => any {
  const value = api[name];
  expect(value, `${name} must be exported`).toBeFunction();
  return value as (...args: any[]) => any;
}

describe("server data-backend contract", () => {
  test("uses sqlite|postgresql and exposes no storage-mode API", () => {
    expect(api.SERVER_DATA_BACKENDS).toEqual(["sqlite", "postgresql"]);
    for (const retired of [
      "STORAGE_MODES",
      "StorageModeSchema",
      "normalizeStorageMode",
      "resolveStorageMode",
      "storageEnvKeys",
    ]) {
      expect(api[retired], `${retired} must be retired`).toBeUndefined();
    }
  });

  test("derives the server backend from database configuration only", () => {
    const resolveServerDataBackend = requiredFunction("resolveServerDataBackend");
    expect(resolveServerDataBackend("demo", {})).toMatchObject({
      backend: "sqlite",
      source: "default",
      databaseUrlPresent: false,
      databaseUrlSource: null,
    });
    expect(
      resolveServerDataBackend("demo", {
        HASNA_DEMO_DATABASE_URL: "postgres://fixture.invalid/demo",
      }),
    ).toMatchObject({
      backend: "postgresql",
      source: "HASNA_DEMO_DATABASE_URL",
      databaseUrlPresent: true,
      databaseUrlSource: "HASNA_DEMO_DATABASE_URL",
    });
  });

  test("legacy storage-mode configuration fails with a migration path", () => {
    const resolveServerDataBackend = requiredFunction("resolveServerDataBackend");
    for (const value of ["cloud", "", "   "]) {
      expect(() =>
        resolveServerDataBackend("demo", { HASNA_DEMO_STORAGE_MODE: value }),
      ).toThrow(/HASNA_DEMO_STORAGE_MODE.*removed.*HASNA_DEMO_DATABASE_URL/i);
    }
  });

  test("service manifests carry storage.backend, never storage.mode", () => {
    const validate = requiredFunction("validateServiceContractManifest");
    const manifest = {
      schema: "hasna.service_contract.v1",
      name: "demo",
      class: "cli-with-store",
      contractVersion: "v1",
      kitVersion: "0.9.0",
      bins: ["demo"],
      storage: {
        backend: "sqlite",
        sqlitePath: "~/.hasna/demo/demo.db",
      },
    };
    expect(validate(manifest).success).toBe(true);
    expect(
      validate({
        ...manifest,
        storage: { mode: "sqlite", sqlitePath: "~/.hasna/demo/demo.db" },
      }).success,
    ).toBe(false);
    expect(
      validate({ ...manifest, storage: { backend: "postgres" } }).success,
    ).toBe(false);
    expect(
      validate({ ...manifest, storage: { backend: "postgresql" } }).success,
    ).toBe(true);
  });
});

describe("client transport contract", () => {
  test("uses sqlite|http and does not expose a server backend as client state", () => {
    expect(api.CLIENT_TRANSPORTS).toEqual(["sqlite", "http"]);
    const resolveClientTransport = requiredFunction("resolveClientTransport");

    const local = resolveClientTransport("demo", {});
    expect(local.transport).toBe("sqlite");
    expect(local.transportSource).toBe("default");
    expect("mode" in local).toBe(false);
    expect("modeSource" in local).toBe(false);

    const http = resolveClientTransport("demo", {
      HASNA_DEMO_API_URL: "https://demo.example.com",
      HASNA_DEMO_API_KEY: "fixture-client-key",
    });
    expect(http.transport).toBe("http");
    expect(http.transportSource).toBe("HASNA_DEMO_API_URL");
    expect(http.baseUrl).toBe("https://demo.example.com/v1");
    expect(JSON.stringify(http)).not.toContain("fixture-client-key");
  });

  test("a legacy mode variable is a migration error, not a routing signal", () => {
    const resolveClientTransport = requiredFunction("resolveClientTransport");
    for (const value of ["postgres", "", "   "]) {
      expect(() =>
        resolveClientTransport("demo", {
          HASNA_DEMO_STORAGE_MODE: value,
          HASNA_DEMO_API_URL: "https://demo.example.com",
          HASNA_DEMO_API_KEY: "fixture-client-key",
        }),
      ).toThrow(/HASNA_DEMO_STORAGE_MODE.*removed.*HASNA_DEMO_API_URL/i);
    }
  });

  test("the client env contract has URL and credential keys, not mode keys", () => {
    const keys = requiredFunction("clientTransportEnvKeys")("demo");
    expect(keys).toEqual({
      apiUrlKeys: ["HASNA_DEMO_API_URL", "DEMO_API_URL"],
      apiKeyKeys: ["HASNA_DEMO_API_KEY", "DEMO_API_KEY"],
    });
  });
});

describe("vendored kit contract", () => {
  test("generates backend.ts and no mode module or mode-gated pool", () => {
    const rendered = renderKit("9.9.9");
    expect(Object.keys(rendered.files)).toContain("backend.ts");
    expect(Object.keys(rendered.files)).not.toContain("mode.ts");
    expect(rendered.files["index.ts"]).toContain('export * from "./backend.js"');
    expect(rendered.files["index.ts"]).not.toContain('./mode.js');
    expect(rendered.files["pool.ts"]).not.toContain("resolveStorageMode");
    expect(rendered.files["pool.ts"]).not.toContain("createCloudPoolFromEnv");
  });
});
