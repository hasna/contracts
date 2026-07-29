import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SCHEMA_IDS,
  SERVICE_CONTRACT_VERSION,
  type ServiceContractManifestInput
} from "../src/schemas";
import { runRepoConformance } from "../src/conformance";

const repoRoot = join(import.meta.dir, "..");

/**
 * Clause C: a package that publishes must bind a packed-artifact scan to
 * `prepack`, and declare which script does it. Both halves are part of what a
 * conformant published package now looks like, so the shared fixtures carry
 * them.
 */
const completeReleaseMetadata = { release: { artifactScan: { script: "scan:artifact" } } };

const completeReleaseScripts = {
  prepack: "bun run verify:release",
  "verify:release": "bun test && bun run scan:artifact",
  "scan:artifact": "bun scripts/scan-artifact.ts"
};

function completeServiceManifest(pgCommand = "bun test tests/postgres-storage.test.ts"): ServiceContractManifestInput {
  return {
    schema: SCHEMA_IDS.serviceContract,
    name: "demo",
    class: "service",
    contractVersion: SERVICE_CONTRACT_VERSION,
    kitVersion: "0.6.0",
    bins: ["demo", "demo-mcp", "demo-serve"],
    hosting: ["user-hosted"],
    storage: {
      mode: "sqlite",
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
      },
      {
        name: "cli",
        kind: "cli",
        status: "supported",
        bin: "demo",
        authMode: "local-only",
      }
    ],
    metadata: { ...completeReleaseMetadata }
  };
}

function cliWithStoreManifest(storage: Record<string, unknown>): ServiceContractManifestInput {
  return {
    schema: SCHEMA_IDS.serviceContract,
    name: "demo",
    class: "cli-with-store",
    contractVersion: SERVICE_CONTRACT_VERSION,
    kitVersion: "0.8.0",
    bins: ["demo"],
    hosting: ["user-hosted"],
    storage: storage as ServiceContractManifestInput["storage"],
    serviceSurfaces: [
      {
        name: "cli",
        kind: "cli",
        status: "supported",
        bin: "demo",
        authMode: "local-only",
      }
    ],
    metadata: { ...completeReleaseMetadata }
  };
}

const cliOnlyPackage = {
  name: "@hasna/demo",
  version: "1.0.0",
  scripts: completeReleaseScripts,
  bin: { demo: "dist/cli.js" },
  exports: { ".": "./dist/index.js" }
};

const completePackage = {
  name: "@hasna/demo",
  version: "1.0.0",
  scripts: completeReleaseScripts,
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
  run: (root: string) => void,
  options: { selfHostArtifact?: boolean } = {}
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
    if (options.selfHostArtifact !== false) {
      writeFileSync(join(root, "docker-compose.yml"), "services: {}\n");
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

  test("fails a removed placement word in the mode env", () => {
    const report = runRepoConformance(repoRoot, { env: { HASNA_CONTRACTS_STORAGE_MODE: "self_hosted" } });
    const mode = report.checks.find((c) => c.id === "mode_enum_compliance");
    expect(mode?.status).toBe("fail");
    expect(mode?.detail).toContain("runtime-placement axis was removed");
  });

  test("validates a serve health sample shape", () => {
    // Simulate a service repo by directly shape-checking the health schema path.
    const report = runRepoConformance(repoRoot, {
      env: {},
      healthSample: { status: "ok", version: "1.0.0", mode: "postgres" }
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

  test("does not force API, SDK, or MCP onto a CLI-only cli-with-store repo", () => {
    const manifest: ServiceContractManifestInput = {
      schema: SCHEMA_IDS.serviceContract,
      name: "demo",
      class: "cli-with-store",
      contractVersion: SERVICE_CONTRACT_VERSION,
      kitVersion: "0.7.0",
      bins: ["demo"],
      hosting: ["user-hosted"],
      storage: {
        mode: "sqlite",
        engines: ["sqlite", "postgres"],
        envPrefix: "HASNA_DEMO_",
        sqlitePath: "~/.hasna/demo/demo.db",
        pgTestGate: {
          envVar: "DEMO_TEST_DATABASE_URL",
          command: "bun test tests/postgres.test.ts"
        }
      },
      serviceSurfaces: [
        {
          name: "cli",
          kind: "cli",
          status: "supported",
          bin: "demo",
          authMode: "local-only",
        }
      ],
      metadata: { ...completeReleaseMetadata }
    };
    const pkg = {
      name: "@hasna/demo",
      version: "1.0.0",
      scripts: completeReleaseScripts,
      bin: { demo: "dist/cli.js" },
      exports: { ".": "./dist/index.js" }
    };

    withRepoFixture(manifest, pkg, (root) => {
      const report = runRepoConformance(root, {
        env: {},
        skipNoCloudScan: true
      });
      expect(
        report.checks.find((check) => check.id === "surface_matrix")?.status
      ).toBe("pass");
      expect(
        report.checks.find((check) => check.id === "service_api_topology")?.status
      ).toBe("skip");
      expect(
        report.checks.find((check) => check.id === "self_host_artifact")?.status
      ).toBe("skip");
      expect(report.ok).toBe(true);
    });
  });

  test("passes the storage gate for a sqlite-only cli-with-store with an explicit postgres waiver", () => {
    const manifest = cliWithStoreManifest({
      mode: "sqlite",
      engines: ["sqlite"],
      envPrefix: "HASNA_DEMO_",
      sqlitePath: "~/.hasna/demo/demo.db"
    });
    manifest.metadata = {
      ...completeReleaseMetadata,
      conformance: {
        waivedStorageEngines: [
          {
            engine: "postgres",
            reason: "SQLite-only local CLI; PostgreSQL is tracked behind the vendored storage kit.",
            reviewedBy: "platform-storage"
          }
        ]
      }
    };
    withRepoFixture(manifest, cliOnlyPackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("pass");
      expect(storage?.detail).toContain("sqlite declared");
      expect(storage?.detail).toContain("postgres explicitly waived: SQLite-only local CLI");
      expect(storage?.detail).toContain("reviewed by platform-storage");
      expect(report.ok).toBe(true);
    });
  });

  test("drops the postgres env-prefix requirement only while postgres is waived", () => {
    const manifest = cliWithStoreManifest({
      mode: "sqlite",
      engines: ["sqlite"],
      sqlitePath: "~/.hasna/demo/demo.db"
    });
    manifest.metadata = {
      ...completeReleaseMetadata,
      conformance: {
        waivedStorageEngines: [{ engine: "postgres", reason: "SQLite-only local CLI." }]
      }
    };
    withRepoFixture(manifest, cliOnlyPackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("pass");
      expect(report.ok).toBe(true);
    });

    const unwaived = cliWithStoreManifest({
      mode: "sqlite",
      sqlitePath: "~/.hasna/demo/demo.db"
    });
    withRepoFixture(unwaived, cliOnlyPackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("fail");
      expect(storage?.detail).toContain("storage.envPrefix is required");
      expect(storage?.detail).toContain("storage.pgTestGate is required");
      expect(report.ok).toBe(false);
    });
  });

  test("keeps the dual-engine and live-PG requirements for a store repo without a waiver", () => {
    const manifest = cliWithStoreManifest({
      mode: "sqlite",
      envPrefix: "HASNA_DEMO_",
      sqlitePath: "~/.hasna/demo/demo.db"
    });
    withRepoFixture(manifest, cliOnlyPackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("fail");
      expect(storage?.detail).toContain("missing storage engines: sqlite, postgres");
      expect(storage?.detail).toContain("pgTestGate");
      expect(report.ok).toBe(false);
    });
  });

  test("fails the storage gate once a postgres waiver has expired", () => {
    const manifest = cliWithStoreManifest({
      mode: "sqlite",
      engines: ["sqlite"],
      envPrefix: "HASNA_DEMO_",
      sqlitePath: "~/.hasna/demo/demo.db"
    });
    manifest.metadata = {
      ...completeReleaseMetadata,
      conformance: {
        waivedStorageEngines: [
          { engine: "postgres", reason: "Waiver lapsed.", expiresAt: "2020-01-01T00:00:00.000Z" }
        ]
      }
    };
    withRepoFixture(manifest, cliOnlyPackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      expect(report.checks.find((check) => check.id === "manifest_valid")?.status).toBe("pass");
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("fail");
      // One remedy, stated once: renew or declare. The expired waiver still
      // answers for postgres, so the report does not also demand the engine,
      // its env prefix, and its live-PG gate.
      expect(storage?.detail).toBe(
        "storage waiver for postgres expired at 2020-01-01T00:00:00.000Z; declare the engine or renew the waiver"
      );
      expect(report.ok).toBe(false);
    });
  });

  test("still requires the live-PG gate when postgres is declared alongside a waiver", () => {
    const manifest = cliWithStoreManifest({
      mode: "sqlite",
      engines: ["sqlite", "postgres"],
      envPrefix: "HASNA_DEMO_",
      sqlitePath: "~/.hasna/demo/demo.db"
    });
    manifest.metadata = {
      ...completeReleaseMetadata,
      conformance: {
        waivedStorageEngines: [{ engine: "postgres", reason: "Redundant waiver next to a declared engine." }]
      }
    };
    withRepoFixture(manifest, cliOnlyPackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("fail");
      expect(storage?.detail).toContain("pgTestGate");
      expect(report.ok).toBe(false);
    });
  });

  test("rejects a waiver for an engine that is never waivable", () => {
    const manifest = cliWithStoreManifest({
      mode: "sqlite",
      engines: ["sqlite", "postgres"],
      envPrefix: "HASNA_DEMO_",
      sqlitePath: "~/.hasna/demo/demo.db",
      pgTestGate: { envVar: "DEMO_TEST_DATABASE_URL", command: "bun test tests/postgres.test.ts" }
    });
    // sqlite is not in the waivable enum at all, so this never reaches the gate.
    manifest.metadata = {
      ...completeReleaseMetadata,
      conformance: {
        waivedStorageEngines: [
          { engine: "sqlite", reason: "Fixture tries to drop the local store." } as unknown as never
        ]
      }
    };
    withRepoFixture(manifest, cliOnlyPackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const valid = report.checks.find((check) => check.id === "manifest_valid");
      expect(valid?.status).toBe("fail");
      expect(valid?.detail).toContain("metadata.conformance.waivedStorageEngines.0.engine");
      expect(report.ok).toBe(false);
    });
  });

  test("locks the no-waiver storage_capabilities detail strings", () => {
    const complete = cliWithStoreManifest({
      mode: "sqlite",
      engines: ["sqlite", "postgres"],
      envPrefix: "HASNA_DEMO_",
      sqlitePath: "~/.hasna/demo/demo.db",
      pgTestGate: { envVar: "DEMO_TEST_DATABASE_URL", command: "bun test tests/postgres.test.ts" }
    });
    withRepoFixture(complete, cliOnlyPackage, (root) => {
      const storage = runRepoConformance(root, { env: {}, skipNoCloudScan: true }).checks.find(
        (check) => check.id === "storage_capabilities"
      );
      expect(storage?.status).toBe("pass");
      expect(storage?.detail).toBe("sqlite and postgres capabilities plus live-PG gate declared");
    });

    const bare = cliWithStoreManifest({ mode: "sqlite", sqlitePath: "~/.hasna/demo/demo.db" });
    withRepoFixture(bare, cliOnlyPackage, (root) => {
      const storage = runRepoConformance(root, { env: {}, skipNoCloudScan: true }).checks.find(
        (check) => check.id === "storage_capabilities"
      );
      expect(storage?.status).toBe("fail");
      expect(storage?.detail).toBe(
        "missing storage engines: sqlite, postgres; storage.envPrefix is required for the PostgreSQL DATABASE_URL contract; storage.pgTestGate is required to prove live PostgreSQL support"
      );
    });

    const library = runRepoConformance(repoRoot, { env: {} }).checks.find(
      (check) => check.id === "storage_capabilities"
    );
    expect(library?.status).toBe("skip");
    expect(library?.detail).toBe("library repo is outside the dual-storage core gate");
  });

  test("rejects storage waivers from a repo whose active backend is PostgreSQL", () => {
    const manifest = cliWithStoreManifest({
      mode: "postgres",
      engines: ["sqlite", "postgres"],
      envPrefix: "HASNA_DEMO_",
      pgTestGate: { envVar: "DEMO_TEST_DATABASE_URL", command: "bun test tests/postgres.test.ts" }
    });
    manifest.metadata = {
      ...completeReleaseMetadata,
      conformance: {
        waivedStorageEngines: [{ engine: "postgres", reason: "Cloud-mode repo tries to drop PostgreSQL." }]
      }
    };
    withRepoFixture(manifest, cliOnlyPackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("fail");
      expect(storage?.detail).toContain("storage waivers are not permitted while storage.mode is postgres");
      expect(report.ok).toBe(false);
    });
  });

  test("rejects storage waivers from a repo declaring the hasna-saas story", () => {
    const saasStory = cliWithStoreManifest({
      mode: "sqlite",
      engines: ["sqlite", "postgres"],
      envPrefix: "HASNA_DEMO_",
      sqlitePath: "~/.hasna/demo/demo.db",
      pgTestGate: { envVar: "DEMO_TEST_DATABASE_URL", command: "bun test tests/postgres.test.ts" }
    });
    saasStory.hosting = ["user-hosted", "hasna-saas"];
    saasStory.metadata = {
      conformance: {
        waivedStorageEngines: [{ engine: "postgres", reason: "SaaS story tries to drop PostgreSQL." }]
      }
    };
    withRepoFixture(saasStory, cliOnlyPackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("fail");
      expect(storage?.detail).toContain("hasna-saas product story");
    });
  });

  test("rejects a storage waiver on a saas manifest", () => {
    const manifest = {
      schema: SCHEMA_IDS.serviceContract,
      name: "demo",
      class: "saas",
      contractVersion: SERVICE_CONTRACT_VERSION,
      kitVersion: "0.8.0",
      bins: ["demo", "demo-mcp", "demo-serve"],
      hosting: ["hasna-saas", "user-hosted"],
      storage: { mode: "postgres", engines: ["sqlite", "postgres"], envPrefix: "HASNA_DEMO_" },
      serviceSurfaces: completeServiceManifest().serviceSurfaces,
      metadata: {
        ...completeReleaseMetadata,
        conformance: {
          waivedStorageEngines: [{ engine: "postgres", reason: "SaaS tries to drop PostgreSQL." }]
        }
      }
    };
    withRepoFixture(manifest, completePackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("fail");
      expect(storage?.detail).toContain("storage waivers are not permitted for class saas");
      expect(report.ok).toBe(false);
    });
  });

  test("treats an empty waiver array as no waiver at all", () => {
    const manifest = cliWithStoreManifest({
      mode: "sqlite",
      engines: ["sqlite", "postgres"],
      envPrefix: "HASNA_DEMO_",
      sqlitePath: "~/.hasna/demo/demo.db",
      pgTestGate: { envVar: "DEMO_TEST_DATABASE_URL", command: "bun test tests/postgres.test.ts" }
    });
    manifest.metadata = { conformance: { waivedStorageEngines: [] } };
    withRepoFixture(manifest, cliOnlyPackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("pass");
      expect(storage?.detail).toBe("sqlite and postgres capabilities plus live-PG gate declared");
    });
  });

  test("still requires an explicit sqlite engine when storage.engines is omitted", () => {
    const manifest = cliWithStoreManifest({
      mode: "sqlite",
      envPrefix: "HASNA_DEMO_",
      sqlitePath: "~/.hasna/demo/demo.db"
    });
    manifest.metadata = {
      ...completeReleaseMetadata,
      conformance: {
        waivedStorageEngines: [{ engine: "postgres", reason: "SQLite-only local CLI." }]
      }
    };
    withRepoFixture(manifest, cliOnlyPackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      expect(report.checks.find((check) => check.id === "manifest_valid")?.status).toBe("pass");
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("fail");
      expect(storage?.detail).toContain("missing storage engines: sqlite");
      expect(report.ok).toBe(false);
    });
  });

  test("evaluates waiver expiry against the injected clock, inclusive of the instant itself", () => {
    const expiresAt = "2030-06-01T00:00:00.000Z";
    const manifest = cliWithStoreManifest({
      mode: "sqlite",
      engines: ["sqlite"],
      sqlitePath: "~/.hasna/demo/demo.db"
    });
    manifest.metadata = {
      ...completeReleaseMetadata,
      conformance: {
        waivedStorageEngines: [{ engine: "postgres", reason: "Time-boxed waiver.", expiresAt }]
      }
    };
    withRepoFixture(manifest, cliOnlyPackage, (root) => {
      const justBefore = runRepoConformance(root, {
        env: {},
        skipNoCloudScan: true,
        now: new Date(Date.parse(expiresAt) - 1)
      });
      expect(justBefore.checks.find((check) => check.id === "storage_capabilities")?.status).toBe("pass");

      const exactly = runRepoConformance(root, {
        env: {},
        skipNoCloudScan: true,
        now: new Date(Date.parse(expiresAt))
      });
      const exactlyStorage = exactly.checks.find((check) => check.id === "storage_capabilities");
      expect(exactlyStorage?.status).toBe("fail");
      expect(exactlyStorage?.detail).toContain("expired at");
    });
  });

  test("fails a waiver whose prose cannot be recorded, in both manifest tiers", () => {
    const internalHost = ["ops@demo", ["hasna", "xyz"].join(".")].join(".");
    const manifest = cliWithStoreManifest({
      mode: "sqlite",
      engines: ["sqlite"],
      sqlitePath: "~/.hasna/demo/demo.db"
    });
    manifest.metadata = {
      ...completeReleaseMetadata,
      conformance: {
        waivedStorageEngines: [
          {
            engine: "postgres",
            reason: "blocked on hasna/oss/demo/database-url in account 123456789012",
            reviewedBy: internalHost
          }
        ]
      }
    };
    withRepoFixture(manifest, cliOnlyPackage, (root) => {
      for (const manifestTier of ["public", "private"] as const) {
        const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true, manifestTier });
        const storage = report.checks.find((check) => check.id === "storage_capabilities");
        // A waiver that cannot be printed cannot be audited, so it fails rather
        // than passing with its justification erased.
        expect(storage?.status).toBe("fail");
        expect(storage?.detail).toContain("storage waiver for postgres cannot be recorded: reason, reviewedBy");
        expect(storage?.detail).not.toContain("hasna/oss/demo/database-url");
        expect(storage?.detail).not.toContain("123456789012");
        expect(storage?.detail).not.toContain(internalHost);
        // The single remedy is stated once; no "build PostgreSQL" noise.
        expect(storage?.detail).not.toContain("missing storage engines");
        expect(report.ok).toBe(false);
      }
      // The public tier still reports the underlying manifest finding.
      const publicReport = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const safety = publicReport.checks.find((check) => check.id === "public_manifest_safety");
      expect(safety?.status).toBe("fail");
      expect(safety?.detail).toContain("metadata.conformance.waivedStorageEngines[0].reason");
    });
  });

  test("rejects storage waivers from a service-capable cli-with-store", () => {
    const manifest = cliWithStoreManifest({
      mode: "sqlite",
      engines: ["sqlite", "postgres"],
      envPrefix: "HASNA_DEMO_",
      sqlitePath: "~/.hasna/demo/demo.db",
      pgTestGate: { envVar: "DEMO_TEST_DATABASE_URL", command: "bun test tests/postgres.test.ts" }
    });
    manifest.bins = ["demo", "demo-serve"];
    manifest.metadata = {
      ...completeReleaseMetadata,
      conformance: {
        waivedStorageEngines: [{ engine: "postgres", reason: "Repo ships a server but wants sqlite only." }]
      }
    };
    withRepoFixture(manifest, { ...cliOnlyPackage, bin: { demo: "dist/cli.js", "demo-serve": "dist/serve.js" } }, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("fail");
      expect(storage?.detail).toContain(
        "storage waivers are not permitted for a service-capable cli-with-store repo shipping demo-serve"
      );
      expect(report.ok).toBe(false);
    });
  });

  test("rejects storage waivers from classes that may not waive an engine", () => {
    const manifest = completeServiceManifest();
    manifest.metadata = {
      ...completeReleaseMetadata,
      conformance: {
        waivedStorageEngines: [{ engine: "postgres", reason: "Services still owe both engines." }]
      }
    };
    withRepoFixture(manifest, completePackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("fail");
      expect(storage?.detail).toContain("storage waivers are not permitted for class service");
      expect(report.ok).toBe(false);
    });
  });

  test("fails a class outside the storage gate that still declares a storage waiver", () => {
    const manifest = {
      schema: SCHEMA_IDS.serviceContract,
      name: "demo",
      class: "library",
      contractVersion: SERVICE_CONTRACT_VERSION,
      kitVersion: "0.8.0",
      bins: ["demo"],
      hosting: ["user-hosted"],
      serviceSurfaces: [
        {
          name: "sdk",
          kind: "sdk",
          status: "supported",
          authMode: "none",
          exportSubpath: "."
        },
        {
          name: "cli",
          kind: "cli",
          status: "supported",
          bin: "demo",
          authMode: "local-only",
        }
      ],
      metadata: {
        ...completeReleaseMetadata,
        conformance: {
          waivedSurfaces: [
            { kind: "api", reason: "Library fixture." },
            { kind: "mcp", reason: "Library fixture." }
          ],
          waivedStorageEngines: [{ engine: "postgres", reason: "Library fixture has no store at all." }]
        }
      }
    };
    withRepoFixture(manifest, cliOnlyPackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const storage = report.checks.find((check) => check.id === "storage_capabilities");
      expect(storage?.status).toBe("fail");
      expect(storage?.detail).toContain("storage waivers are not permitted for class library");
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
      ...completeReleaseMetadata,
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
      ...completeReleaseMetadata,
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
          exportSubpath: "."
        },
        {
          name: "cli",
          kind: "cli",
          status: "supported",
          bin: "demo",
          authMode: "local-only",
        }
      ],
      metadata: {
        ...completeReleaseMetadata,
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
      scripts: completeReleaseScripts,
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

  test("section 3 and section 6 agree: contract-mandated env NAMES are not credential values", () => {
    // These were flagged as leaked credentials by the previous detector,
    // case-insensitively, on live manifests (open-loops, open-sessions,
    // iapp-sessions, iapp-domains): `HASNA_LOOPS_DATABASE_URL` matched because
    // `DATABASE_URL` is exactly 12 characters. Section 3 REQUIRES those names.
    // A mandatory gate that fires on compliant repos gets switched off, and
    // then it protects nothing.
    const manifest = {
      ...completeServiceManifest(),
      metadata: {
        ...completeReleaseMetadata,
        // Keys that NAME a variable. The carve-out is anchored to these, not
        // to any credential-shaped key whose value happens to be upper-snake.
        env: {
          modeEnvVar: "HASNA_DEMO_STORAGE_MODE",
          databaseUrlEnvVar: "HASNA_DEMO_DATABASE_URL",
          apiBaseUrlEnvVar: "HASNA_DEMO_API_BASE_URL",
          identityJwksUriEnvVar: "HASNA_DEMO_IDENTITY_JWKS_URI",
          signingKeyEnvName: "HASNA_DEMO_API_SIGNING_KEY"
        }
      }
    };
    withRepoFixture(manifest, completePackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const safety = report.checks.find((check) => check.id === "public_manifest_safety");
      expect(safety?.status).toBe("pass");
    });
  });

  test("the env-name carve-out does not hide an upper-snake SECRET", () => {
    // `apiKey` names a credential, not a variable. Before the carve-out was
    // anchored to variable-naming keys, any upper-snake value under any
    // credential-shaped key passed silently.
    const manifest = {
      ...completeServiceManifest(),
      metadata: { ...completeReleaseMetadata, apiKey: "PRODUCTION_KEY_MATERIAL_A1B2C3" }
    };
    withRepoFixture(manifest, completePackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const safety = report.checks.find((check) => check.id === "public_manifest_safety");
      expect(safety?.status).toBe("fail");
      expect(safety?.detail).toContain("metadata.apiKey");
    });
  });

  test("a genuinely leaked API key is still caught", () => {
    // The corrected detector is the real token grammar from src/auth/keys.ts:
    // lowercase namespace and app slug, and a signature segment. Strictly
    // better at finding tokens than the pattern it replaced.
    const leaked = [["hasna", "demo", "cGxhY2Vob2xkZXJib2R5dmFsdWU"].join("_"), "c2lnbmF0dXJlLXBsYWNlaG9sZGVy"].join(".");
    const manifest = {
      ...completeServiceManifest(),
      metadata: { ...completeReleaseMetadata, note: `bootstrap with ${leaked}` }
    };
    withRepoFixture(manifest, completePackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const safety = report.checks.find((check) => check.id === "public_manifest_safety");
      expect(safety?.status).toBe("fail");
      expect(safety?.detail).toContain("metadata.note (credential-value)");
      expect(safety?.detail).not.toContain(leaked);
    });
  });

  test("redacts public-manifest safety findings and supports explicit private-tier inspection", () => {
    const internalDomain = ["hasna", "xyz"].join(".");
    const credentialReference = ["vault", "//team/demo/provider"].join(":");
    // A REAL-shaped Hasna API key: `hasna_<app>_<body>.<signature>`. The old
    // detector matched `hasna_demo_<anything 12+ chars>` case-insensitively,
    // which is why it also flagged `HASNA_DEMO_DATABASE_URL` — the env name
    // CONTRACT.md section 3 requires. The fixture now carries the shape a
    // leaked key actually has, so the test proves the guard catches one.
    const credentialValue = [
      ["hasna", "demo", "cGxhY2Vob2xkZXJib2R5dmFsdWU"].join("_"),
      "c2lnbmF0dXJlLXBsYWNlaG9sZGVy"
    ].join(".");
    const manifest = {
      ...completeServiceManifest(),
      storage: {
        ...completeServiceManifest().storage,
        databaseUrlSecretRef: "hasna/oss/demo/database-url"
      },
      metadata: {
        ...completeReleaseMetadata,
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

  test("rejects segmented credential keys and token-shaped values without echoing values", () => {
    const jwtFixture = [
      "eyJmaXh0dXJlIjoidGVzdCJ9",
      "eyJzdWIiOiJwbGFjZWhvbGRlciJ9",
      "c2FmZS1maXh0dXJlLXNpZ25hdHVyZQ"
    ].join(".");
    const cases: Array<{
      metadata: Record<string, unknown>;
      expectedFinding: string;
      redactedValue: string;
    }> = [
      {
        metadata: { "auth.credential.value": jwtFixture },
        expectedFinding: "metadata.auth.credential.value (credential-value)",
        redactedValue: jwtFixture
      },
      {
        metadata: { "auth/token/reference": "provider-entry" },
        expectedFinding: "metadata.auth/token/reference (credential-ref)",
        redactedValue: "provider-entry"
      },
      {
        metadata: { auth: { credential: { value: jwtFixture } } },
        expectedFinding: "metadata.auth.credential.value (credential-value)",
        redactedValue: jwtFixture
      },
      {
        metadata: { api: { key: "provider-entry" } },
        expectedFinding: "metadata.api.key (credential-value)",
        redactedValue: "provider-entry"
      },
      {
        metadata: { access: { key: "provider-entry" } },
        expectedFinding: "metadata.access.key (credential-value)",
        redactedValue: "provider-entry"
      },
      {
        metadata: { database: { url: "postgres://db.example.invalid/app" } },
        expectedFinding: "metadata.database.url (credential-value)",
        redactedValue: "postgres://db.example.invalid/app"
      }
    ];

    for (const fixture of cases) {
      withRepoFixture(
        { ...completeServiceManifest(), metadata: fixture.metadata },
        completePackage,
        (root) => {
          const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
          const safety = report.checks.find((check) => check.id === "public_manifest_safety");
          expect(safety?.status).toBe("fail");
          expect(safety?.detail).toContain(fixture.expectedFinding);
          expect(safety?.detail).not.toContain(fixture.redactedValue);
        }
      );
    }

    withRepoFixture(
      {
        ...completeServiceManifest(),
        metadata: {
          ...completeReleaseMetadata,
          "documentation.tokenization.value": "public-example",
          exampleSegments: "eyJzaG9ydCJ9.not-a-token"
        }
      },
      completePackage,
      (root) => {
        const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
        expect(report.checks.find((check) => check.id === "public_manifest_safety")?.status).toBe("pass");
      }
    );
  });

  test("requires a self-host deployment artifact for service-class repositories", () => {
    withRepoFixture(
      completeServiceManifest(),
      completePackage,
      (root) => {
        const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
        const artifact = report.checks.find((check) => check.id === "self_host_artifact");
        expect(artifact?.status).toBe("fail");
        expect(artifact?.detail).toContain("docker-compose.yml");
        expect(report.ok).toBe(false);
      },
      { selfHostArtifact: false }
    );
  });

  test("requires SaaS storage to declare its public DATABASE_URL env prefix", () => {
    const manifest = completeServiceManifest();
    manifest.class = "saas";
    manifest.hosting = ["hasna-saas"];
    manifest.storage = { mode: "postgres" };

    withRepoFixture(manifest, completePackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const manifestCheck = report.checks.find((check) => check.id === "manifest_valid");
      expect(manifestCheck?.status).toBe("fail");
      expect(manifestCheck?.detail).toContain("storage.envPrefix");
      expect(report.ok).toBe(false);
    });
  });

  test("requires a saas manifest to declare the hasna-saas hosting story", () => {
    const { hosting: _hosting, ...manifest } = completeServiceManifest();
    manifest.class = "saas";
    if (!manifest.storage) throw new Error("complete service fixture is missing storage");
    manifest.storage.mode = "postgres";
    withRepoFixture(manifest, completePackage, (root) => {
      const report = runRepoConformance(root, { env: {}, skipNoCloudScan: true });
      const hosting = report.checks.find((check) => check.id === "hosting_story");
      expect(hosting?.status).toBe("fail");
      expect(hosting?.detail).toContain("hasna-saas");
      expect(report.ok).toBe(false);
    });
  });
});
