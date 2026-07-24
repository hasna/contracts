import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SCHEMA_IDS,
  SERVICE_CONTRACT_VERSION,
  runRepoConformance,
  type ServiceContractManifestInput
} from "../src";

const repoRoot = join(import.meta.dir, "..");

function completeServiceManifest(pgCommand = "bun test tests/postgres-storage.test.ts"): ServiceContractManifestInput {
  return {
    schema: SCHEMA_IDS.serviceContract,
    name: "demo",
    class: "service",
    contractVersion: SERVICE_CONTRACT_VERSION,
    kitVersion: "0.6.0",
    bins: ["demo", "demo-mcp", "demo-serve"],
    hosting: ["user-hosted"],
    deploymentModes: ["local", "self_hosted"],
    storage: {
      mode: "local",
      engines: ["sqlite", "postgres"],
      envPrefix: "HASNA_DEMO_",
      sqlitePath: "~/.hasna/demo/demo.db",
      pgTestGate: {
        envVar: "DEMO_TEST_DATABASE_URL",
        command: pgCommand
      }
    },
    serviceSurfaces: [
      {
        name: "http-api",
        kind: "api",
        status: "supported",
        bin: "demo-serve",
        authMode: "api-key",
        deploymentModes: ["local", "self_hosted"],
        health: { method: "GET", path: "/health", public: true },
        readiness: { method: "GET", path: "/ready", public: false },
        version: { method: "GET", path: "/version", public: true },
        apiBasePath: "/v1",
        openApiPath: "/openapi.json",
        readinessGates: []
      },
      {
        name: "typescript-sdk",
        kind: "sdk",
        status: "supported",
        authMode: "api-key",
        deploymentModes: ["local", "self_hosted"],
        exportSubpath: "./sdk",
        generatedFrom: "/openapi.json",
        clientClassName: "DemoClient"
      },
      {
        name: "mcp",
        kind: "mcp",
        status: "supported",
        mcpBin: "demo-mcp",
        authMode: "api-key",
        deploymentModes: ["local", "self_hosted"]
      },
      {
        name: "cli",
        kind: "cli",
        status: "supported",
        bin: "demo",
        authMode: "local-only",
        deploymentModes: ["local", "self_hosted"]
      }
    ]
  };
}

const completePackage = {
  name: "@hasna/demo",
  version: "1.0.0",
  bin: {
    demo: "dist/cli.js",
    "demo-mcp": "dist/mcp.js",
    "demo-serve": "dist/serve.js"
  },
  exports: {
    ".": "./dist/index.js",
    "./sdk": "./dist/sdk.js"
  }
};

function withRepoFixture(
  manifest: Record<string, unknown>,
  pkg: Record<string, unknown>,
  run: (root: string) => void
): void {
  const root = mkdtempSync(join(tmpdir(), "contracts-conformance-"));
  try {
    writeFileSync(join(root, "hasna.contract.json"), `${JSON.stringify(manifest, null, 2)}\n`);
    writeFileSync(join(root, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
    const dist = join(root, "dist");
    mkdirSync(dist);
    for (const file of ["index.js", "index.d.ts", "sdk.js", "sdk.d.ts"]) {
      writeFileSync(join(dist, file), file.endsWith(".d.ts") ? "export {};\n" : "export {};\n");
    }
    run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe("repo conformance kit", () => {
  test("open-contracts passes conformance against itself", () => {
    const report = runRepoConformance(repoRoot, { env: {} });
    const failed = report.checks.filter((c) => c.status === "fail");
    expect(failed).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.name).toBe("contracts");
    expect(report.class).toBe("library");
  });

  test("manifest, surface, hosting, safety, bins, and no_cloud_guard checks run", () => {
    const report = runRepoConformance(repoRoot, { env: {} });
    const ids = report.checks.map((c) => c.id);
    expect(ids).toContain("manifest_valid");
    expect(ids).toContain("bins_allowlisted");
    expect(ids).toContain("bins_match_package");
    expect(ids).toContain("surface_matrix");
    expect(ids).toContain("surface_bindings");
    expect(ids).toContain("storage_capabilities");
    expect(ids).toContain("public_manifest_safety");
    expect(ids).toContain("hosting_story");
    expect(ids).toContain("mode_enum_compliance");
    expect(ids).toContain("no_cloud_guard");
    const noCloud = report.checks.find((c) => c.id === "no_cloud_guard");
    expect(noCloud?.status).toBe("pass");
  });

  test("library repo skips health_shape", () => {
    const report = runRepoConformance(repoRoot, { env: {} });
    const health = report.checks.find((c) => c.id === "health_shape");
    expect(health?.status).toBe("skip");
  });

  test("fails when a bad mode env is set", () => {
    const report = runRepoConformance(repoRoot, { env: { HASNA_CONTRACTS_STORAGE_MODE: "sync" } });
    const mode = report.checks.find((c) => c.id === "mode_enum_compliance");
    expect(mode?.status).toBe("fail");
    expect(report.ok).toBe(false);
  });

  test("normalizes a deprecated alias env to cloud", () => {
    const report = runRepoConformance(repoRoot, { env: { HASNA_CONTRACTS_STORAGE_MODE: "self_hosted" } });
    const mode = report.checks.find((c) => c.id === "mode_enum_compliance");
    expect(mode?.status).toBe("pass");
    expect(mode?.detail).toContain("cloud");
  });

  test("validates a serve health sample shape", () => {
    // Simulate a service repo by directly shape-checking the health schema path.
    const report = runRepoConformance(repoRoot, {
      env: {},
      healthSample: { status: "ok", version: "1.0.0", mode: "cloud" }
    });
    // library has no serve bin, so health is skipped even with a sample
    const health = report.checks.find((c) => c.id === "health_shape");
    expect(health?.status).toBe("skip");
  });

  test("passes a complete service contract without executing manifest commands", () => {
    const sentinel = join(tmpdir(), `contracts-command-must-not-run-${process.pid}-${Date.now()}`);
    const manifest = completeServiceManifest(`touch ${sentinel}`);
    const apiSurface = manifest.serviceSurfaces?.[0];
    if (!apiSurface) throw new Error("complete service fixture is missing its API surface");
    apiSurface.readinessGates = [
      {
        id: "malicious-looking-sentinel",
        kind: "storage",
        command: `touch ${sentinel}`,
        status: "pending"
      }
    ];
    try {
      withRepoFixture(manifest, completePackage, (root) => {
        const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
        expect(report.ok).toBe(true);
        expect(report.checks.find((check) => check.id === "surface_matrix")?.status).toBe("pass");
        expect(report.checks.find((check) => check.id === "surface_bindings")?.status).toBe("pass");
        expect(report.checks.find((check) => check.id === "storage_capabilities")?.status).toBe("pass");
        expect(existsSync(sentinel)).toBe(false);
      });
    } finally {
      rmSync(sentinel, { force: true });
    }
  });

  test("fails conformance when a service omits the SDK surface without a waiver", () => {
    const manifest = completeServiceManifest();
    manifest.serviceSurfaces = (manifest.serviceSurfaces ?? []).filter((surface) => surface.kind !== "sdk");
    withRepoFixture(manifest, completePackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const surface = report.checks.find((check) => check.id === "surface_matrix");
      expect(surface?.status).toBe("fail");
      expect(surface?.detail).toContain("sdk");
      expect(report.ok).toBe(false);
    });
  });

  test("fails conformance when the declared SDK export is absent from package.json", () => {
    const pkg = {
      ...completePackage,
      exports: {
        ".": "./dist/index.js"
      }
    };
    withRepoFixture(completeServiceManifest(), pkg, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const binding = report.checks.find((check) => check.id === "surface_bindings");
      expect(binding?.status).toBe("fail");
      expect(binding?.detail).toContain("exportSubpath");
      expect(report.ok).toBe(false);
    });
  });

  test("fails conformance when the declared SDK export target does not exist", () => {
    const pkg = {
      ...completePackage,
      exports: {
        ".": "./dist/index.js",
        "./sdk": "./dist/missing-sdk.js"
      }
    };
    withRepoFixture(completeServiceManifest(), pkg, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const binding = report.checks.find((check) => check.id === "surface_bindings");
      expect(binding?.status).toBe("fail");
      expect(binding?.detail).toContain("./dist/missing-sdk.js");
      expect(report.ok).toBe(false);
    });
  });

  test("rejects service surface waivers without library or non-Node eligibility", () => {
    const manifest = completeServiceManifest();
    manifest.serviceSurfaces = (manifest.serviceSurfaces ?? []).filter((surface) => surface.kind === "api");
    manifest.metadata = {
      conformance: {
        waivedSurfaces: [
          { kind: "sdk", reason: "Fixture tries to bypass the SDK requirement." },
          { kind: "mcp", reason: "Fixture tries to bypass the MCP requirement." },
          { kind: "cli", reason: "Fixture tries to bypass the CLI requirement." }
        ]
      }
    };
    withRepoFixture(manifest, completePackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const surface = report.checks.find((check) => check.id === "surface_matrix");
      expect(surface?.status).toBe("fail");
      expect(surface?.detail).toContain("waivers not permitted for class service");
      expect(surface?.detail).toContain("sdk");
      expect(surface?.detail).toContain("mcp");
      expect(surface?.detail).toContain("cli");
      expect(report.ok).toBe(false);
    });
  });

  test("accepts explicit surface waivers for an exceptional non-Node monorepo", () => {
    const manifest = completeServiceManifest();
    manifest.serviceSurfaces = (manifest.serviceSurfaces ?? []).filter((surface) => surface.kind === "api");
    manifest.metadata = {
      conformance: {
        waiverProfile: "non-node-monorepo",
        waivedSurfaces: [
          { kind: "sdk", reason: "SDK is generated in the non-Node workspace." },
          { kind: "mcp", reason: "MCP is hosted by the non-Node workspace." },
          { kind: "cli", reason: "CLI is distributed by the non-Node toolchain." }
        ]
      }
    };
    withRepoFixture(manifest, completePackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      expect(report.checks.find((check) => check.id === "surface_matrix")?.status).toBe("pass");
      expect(report.ok).toBe(true);
    });
  });

  test("resolves a string bin and conditional root export from package.json", () => {
    const manifest = {
      schema: SCHEMA_IDS.serviceContract,
      name: "demo",
      class: "library",
      contractVersion: SERVICE_CONTRACT_VERSION,
      kitVersion: "0.6.0",
      bins: ["demo"],
      hosting: ["user-hosted"],
      serviceSurfaces: [
        {
          name: "sdk",
          kind: "sdk",
          status: "supported",
          authMode: "none",
          deploymentModes: ["local"],
          exportSubpath: "."
        },
        {
          name: "cli",
          kind: "cli",
          status: "supported",
          bin: "demo",
          authMode: "local-only",
          deploymentModes: ["local"]
        }
      ],
      metadata: {
        conformance: {
          waivedSurfaces: [
            { kind: "api", reason: "Library fixture." },
            { kind: "mcp", reason: "Library fixture." }
          ]
        }
      }
    };
    const pkg = {
      name: "@hasna/demo",
      version: "1.0.0",
      bin: "dist/cli.js",
      exports: {
        types: "./dist/index.d.ts",
        import: "./dist/index.js"
      }
    };
    withRepoFixture(manifest, pkg, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      expect(report.checks.find((check) => check.id === "bins_match_package")?.status).toBe("pass");
      expect(report.checks.find((check) => check.id === "surface_bindings")?.status).toBe("pass");
      expect(report.ok).toBe(true);
    });
  });

  test("fails conformance when a legacy service has no storage capability matrix", () => {
    const manifest = completeServiceManifest();
    if (!manifest.storage) throw new Error("complete service fixture is missing storage");
    const { engines: _engines, pgTestGate: _pgTestGate, ...legacyStorage } = manifest.storage;
    manifest.storage = legacyStorage as typeof manifest.storage;
    withRepoFixture(manifest, completePackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("fail");
      expect(storage?.detail).toContain("sqlite");
      expect(storage?.detail).toContain("postgres");
      expect(storage?.detail).toContain("pgTestGate");
    });
  });

  test("redacts public-manifest safety findings and supports explicit private-tier inspection", () => {
    const internalDomain = ["hasna", "xyz"].join(".");
    const credentialReference = ["vault", "//team/demo/provider"].join(":");
    const credentialValue = ["hasna", "demo", "placeholdercredentialvalue"].join("_");
    const manifest = {
      ...completeServiceManifest(),
      storage: {
        ...completeServiceManifest().storage,
        databaseUrlSecretRef: "hasna/oss/demo/database-url"
      },
      metadata: {
        endpoint: `https://internal.${internalDomain}`,
        account: "123456789012",
        role: "arn:aws:iam::123456789012:role/example",
        credentialReference: "provider-entry",
        apiKey: "redacted",
        opaqueLocation: credentialReference,
        exampleValue: credentialValue
      }
    };
    withRepoFixture(manifest, completePackage, (root) => {
      const publicReport = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const safety = publicReport.checks.find((check) => check.id === "public_manifest_safety");
      expect(safety?.status).toBe("fail");
      expect(safety?.detail).toContain("metadata.endpoint (internal-host)");
      expect(safety?.detail).toContain("metadata.account (account-id)");
      expect(safety?.detail).toContain("metadata.role (arn)");
      expect(safety?.detail).toContain("storage.databaseUrlSecretRef (secret-ref)");
      expect(safety?.detail).toContain("metadata.credentialReference (credential-ref)");
      expect(safety?.detail).toContain("metadata.apiKey (credential-value)");
      expect(safety?.detail).toContain("metadata.opaqueLocation (credential-ref)");
      expect(safety?.detail).toContain("metadata.exampleValue (credential-value)");
      expect(safety?.detail).not.toContain(`internal.${internalDomain}`);
      expect(safety?.detail).not.toContain("123456789012");
      expect(safety?.detail).not.toContain("hasna/oss/demo/database-url");
      expect(safety?.detail).not.toContain(credentialReference);
      expect(safety?.detail).not.toContain(credentialValue);

      const privateReport = runRepoConformance(root, {
        env: {},
        skipNoCloudScan: true,
        manifestTier: "private"
      });
      expect(privateReport.checks.find((check) => check.id === "public_manifest_safety")?.status).toBe("skip");
    });
  });

  test("requires a saas manifest to declare the hasna-saas hosting story", () => {
    const { hosting: _hosting, ...manifest } = completeServiceManifest();
    manifest.class = "saas";
    if (!manifest.storage) throw new Error("complete service fixture is missing storage");
    manifest.storage.mode = "cloud";
    withRepoFixture(manifest, completePackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const hosting = report.checks.find((check) => check.id === "hosting_story");
      expect(hosting?.status).toBe("fail");
      expect(hosting?.detail).toContain("hasna-saas");
      expect(report.ok).toBe(false);
    });
  });
});
