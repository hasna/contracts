import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function runContracts(args: string[]) {
  return Bun.spawnSync(["bun", "run", "src/cli/index.ts", ...args], {
    cwd: import.meta.dir + "/..",
    stdout: "pipe",
    stderr: "pipe"
  });
}

function parseStdoutJson(result: ReturnType<typeof runContracts>) {
  return JSON.parse(result.stdout.toString());
}

function expectedFixtureCount() {
  return readdirSync(join(import.meta.dir, "..", "examples")).filter((file) => file.endsWith(".valid.json") || file.endsWith(".invalid.json")).length;
}

describe("contracts CLI", () => {
  test("lists schemas", () => {
    const result = runContracts(["schemas"]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout.toString()).toContain("hasna.proof_bundle.v1");
  });

  test("validates with embedded schema", () => {
    const result = runContracts(["validate", "examples/evidence-ref.valid.json"]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout.toString()).toContain("ok hasna.evidence_ref.v1");
  });

  test("validates with equals-form schema option and JSON output", () => {
    const result = runContracts(["validate", "--json", "--schema=hasna.evidence_ref.v1", "examples/evidence-ref.valid.json"]);
    expect(result.exitCode).toBe(0);
    expect(parseStdoutJson(result).ok).toBe(true);
  });

  test("fails invalid fixtures directly", () => {
    const result = runContracts(["validate", "examples/proof-bundle.invalid.json"]);
    expect(result.exitCode).toBe(1);
  });

  test("reports missing embedded schema as usage error", () => {
    const result = runContracts(["validate", "--json", "package.json"]);
    expect(result.exitCode).toBe(2);
    const payload = parseStdoutJson(result);
    expect(payload.ok).toBe(false);
    expect(payload.code).toBe("unknown_schema");
    expect(payload.error).toContain("No schema provided");
    expect(result.stderr.toString()).toBe("");
  });

  test("reports parser errors as JSON when requested", () => {
    const missingArg = runContracts(["validate", "--json"]);
    expect(missingArg.exitCode).not.toBe(0);
    expect(parseStdoutJson(missingArg).ok).toBe(false);
    expect(missingArg.stderr.toString()).toBe("");

    const unknownOption = runContracts(["schemas", "--json", "--bogus"]);
    expect(unknownOption.exitCode).not.toBe(0);
    expect(parseStdoutJson(unknownOption).ok).toBe(false);
    expect(unknownOption.stderr.toString()).toBe("");
  });

  test("runs example conformance", () => {
    const result = runContracts(["conformance", "--json", "examples"]);
    expect(result.exitCode).toBe(0);
    const payload = parseStdoutJson(result);
    expect(payload.checked).toBe(expectedFixtureCount());
    expect(payload.failed).toBe(0);
    expect(payload.results.some((entry: { schema: string | null }) => entry.schema === null)).toBe(false);
    expect(
      payload.results.some((entry: { file: string; expectedValid: boolean }) => entry.file.endsWith("proof-bundle.invalid.json") && !entry.expectedValid)
    ).toBe(true);
  });

  test("runs repo conformance with stable capability check ids", () => {
    const result = runContracts(["repo-conformance", "--json", "."]);
    expect(result.exitCode).toBe(0);
    expect(result.stderr.toString()).toBe("");
    const payload = parseStdoutJson(result);
    expect(payload.ok).toBe(true);
    expect(payload.checks.map((check: { id: string }) => check.id)).toEqual(
      expect.arrayContaining([
        "manifest_valid",
        "surface_matrix",
        "surface_bindings",
        "storage_capabilities",
        "public_manifest_safety",
        "hosting_story"
      ])
    );
  });

  test("repo conformance exits 1 with clear missing-surface diagnostics", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-repo-conformance-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({
          name: "@hasna/demo",
          version: "1.0.0",
          bin: { demo: "dist/cli.js" },
          exports: { ".": "./dist/index.js" }
        })
      );
      writeFileSync(
        join(dir, "hasna.contract.json"),
        JSON.stringify({
          schema: "hasna.service_contract.v1",
          name: "demo",
          class: "library",
          contractVersion: "v1",
          kitVersion: "0.6.0",
          bins: ["demo"],
          hosting: ["user-hosted"],
          serviceSurfaces: [
            {
              name: "cli",
              kind: "cli",
              status: "supported",
              bin: "demo",
              authMode: "local-only",
              deploymentModes: ["local"]
            }
          ]
        })
      );

      const result = runContracts(["repo-conformance", "--json", dir]);
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toBe("");
      const payload = parseStdoutJson(result);
      const surface = payload.checks.find((check: { id: string }) => check.id === "surface_matrix");
      expect(surface.status).toBe("fail");
      expect(surface.detail).toContain("api");
      expect(surface.detail).toContain("sdk");
      expect(surface.detail).toContain("mcp");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fails conformance on malformed invalid fixture JSON", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-cli-"));
    try {
      writeFileSync(join(dir, "malformed.invalid.json"), "{");
      const result = runContracts(["conformance", dir]);
      expect(result.exitCode).toBe(1);
      expect(result.stdout.toString()).toContain("malformed.invalid.json");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fails conformance on empty fixture sets", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-cli-"));
    try {
      const result = runContracts(["conformance", "--json", dir]);
      expect(result.exitCode).toBe(2);
      const payload = parseStdoutJson(result);
      expect(payload.code).toBe("no_fixtures");
      expect(payload.checked).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fails conformance when invalid fixture has unknown schema", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-cli-"));
    try {
      writeFileSync(join(dir, "unknown-schema.invalid.json"), JSON.stringify({ schema: "hasna.missing.v1" }));
      const result = runContracts(["conformance", "--json", dir]);
      expect(result.exitCode).toBe(1);
      const payload = parseStdoutJson(result);
      expect(payload.failed).toBe(1);
      expect(payload.results[0].schema).toBe(null);
      expect(payload.results[0].error).toContain("missing or unknown embedded schema");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("runs no-cloud scan and emits evidence pack JSON", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    try {
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@hasna/example", version: "0.1.0", dependencies: { zod: "^3.25.0" } }));
      const result = runContracts(["no-cloud-scan", "--json", dir]);
      expect(result.exitCode).toBe(0);
      const payload = parseStdoutJson(result);
      expect(payload.schema).toBe("hasna.no_cloud_evidence_pack.v1");
      expect(payload.verdict).toBe("passed");
      expect(payload.packageName).toBe("@hasna/example");
      expect(payload.subject.uri).toBe("repo://@hasna/example");
      expect(payload.checks.every((check: { target: string }) => check.target.startsWith("repo://@hasna/example#"))).toBe(true);
      expect(JSON.stringify(payload)).not.toContain(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("validates app cloud manifest during no-cloud scan", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    try {
      const manifestPath = join(dir, "app-cloud-manifest.json");
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@hasna/example", version: "0.1.0", dependencies: { zod: "^3.25.0" } }));
      writeFileSync(
        manifestPath,
        JSON.stringify({
          schema: "hasna.app_cloud_manifest.v1",
          id: "cloud_manifest_example",
          createdAt: "2026-06-28T20:10:00.000Z",
          packageName: "@hasna/example",
          appId: "example",
          storageMode: "app_owned_cloud",
          cloudBoundary: "app_owned",
          cloudResources: [
            {
              id: "example-db",
              provider: "aws",
              kind: "database",
              ownerPackage: "@hasna/example"
            }
          ],
          forbiddenSharedRuntimes: ["@hasna/cloud", "open-cloud"],
          dependencies: ["zod"]
        })
      );
      const result = runContracts(["no-cloud-scan", "--json", "--manifest", manifestPath, dir]);
      expect(result.exitCode).toBe(0);
      const payload = parseStdoutJson(result);
      expect(payload.appCloudManifest.packageName).toBe("@hasna/example");
      expect(payload.checks.some((check: { kind: string; status: string }) => check.kind === "app_cloud_manifest" && check.status === "succeeded")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("reports empty manifest arguments in no-cloud scan", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    try {
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@hasna/example", version: "0.1.0" }));
      const result = runContracts(["no-cloud-scan", "--manifest=", dir]);
      expect(result.exitCode).toBe(2);
      expect(result.stderr.toString()).toContain("option '--manifest <file>' argument missing");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fails no-cloud scan on forbidden shared cloud runtime dependencies", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    try {
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@hasna/example", dependencies: { "@hasna/cloud": "0.1.41" } }));
      const result = runContracts(["no-cloud-scan", "--json", dir]);
      expect(result.exitCode).toBe(1);
      const payload = parseStdoutJson(result);
      expect(payload.verdict).toBe("failed");
      expect(payload.findings.some((finding: { pattern: string }) => finding.pattern === "@hasna/cloud")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fails no-cloud scan on forbidden package identity, dev dependency, and source references", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    try {
      mkdirSync(join(dir, "src"));
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "open-cloud", devDependencies: { "@hasna/cloud": "0.1.41" } }));
      writeFileSync(join(dir, "src", "index.ts"), "export const sharedRuntime = 'open-cloud';\n");
      const result = runContracts(["no-cloud-scan", "--json", dir]);
      expect(result.exitCode).toBe(1);
      const payload = parseStdoutJson(result);
      expect(payload.verdict).toBe("failed");
      expect(payload.findings.some((finding: { message: string }) => finding.message.includes("Package identity"))).toBe(true);
      expect(payload.findings.some((finding: { pattern: string; severity: string }) => finding.pattern === "@hasna/cloud" && finding.severity === "high")).toBe(true);
      expect(payload.findings.some((finding: { pattern: string; kind: string }) => finding.pattern === "open-cloud" && finding.kind === "source_import")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fails no-cloud scan on root entrypoints and runtime config paths", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    try {
      mkdirSync(join(dir, ".hasna", "cloud"), { recursive: true });
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@hasna/example", version: "0.1.0" }));
      writeFileSync(join(dir, "index.js"), "registerCloudTools();\n");
      writeFileSync(join(dir, "wrangler.toml"), "name = 'open-cloud'\n");
      writeFileSync(join(dir, ".env.local"), "HASNA_CLOUD_URL=https://example.invalid\n");
      writeFileSync(join(dir, ".hasna", "cloud", "config"), "{}\n");
      const result = runContracts(["no-cloud-scan", "--json", dir]);
      expect(result.exitCode).toBe(1);
      const payload = parseStdoutJson(result);
      expect(payload.findings.some((finding: { path: string; pattern: string }) => finding.path === "index.js" && finding.pattern === "registerCloudTools")).toBe(true);
      expect(payload.findings.some((finding: { path: string; pattern: string }) => finding.path === "wrangler.toml" && finding.pattern === "open-cloud")).toBe(true);
      expect(payload.findings.some((finding: { path: string; pattern: string }) => finding.path === ".env.local" && finding.pattern === "HASNA_CLOUD_")).toBe(true);
      expect(payload.findings.some((finding: { path: string; pattern: string }) => finding.path === ".hasna/cloud/config" && finding.pattern === ".hasna/cloud")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fails no-cloud scan on packed root artifacts", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    const packDir = mkdtempSync(join(tmpdir(), "contracts-pack-"));
    const tarball = join(packDir, "bad.tgz");
    try {
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@hasna/example", version: "0.1.0" }));
      writeFileSync(join(dir, "index.js"), "registerCloudCommands();\n");
      execFileSync("tar", ["-czf", tarball, "-C", dir, "."]);
      const result = runContracts(["no-cloud-scan", "--json", tarball]);
      expect(result.exitCode).toBe(1);
      const payload = parseStdoutJson(result);
      expect(payload.scanMode).toBe("packed_artifact");
      expect(payload.subject.uri).toBe("artifact://bad.tgz");
      expect(payload.findings.some((finding: { path: string; kind: string; pattern: string }) => finding.path === "index.js" && finding.kind === "packed_artifact" && finding.pattern === "registerCloudCommands")).toBe(true);
      expect(JSON.stringify(payload)).not.toContain(dir);
      expect(JSON.stringify(payload)).not.toContain(packDir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(packDir, { recursive: true, force: true });
    }
  });

  test("fails no-cloud scan on packed artifacts with a single archive root directory", () => {
    const parent = mkdtempSync(join(tmpdir(), "contracts-pack-parent-"));
    const packDir = join(parent, "hasna-example-0.1.0");
    const outDir = mkdtempSync(join(tmpdir(), "contracts-pack-out-"));
    const tarball = join(outDir, "bad-root.tgz");
    try {
      mkdirSync(packDir);
      writeFileSync(join(packDir, "package.json"), JSON.stringify({ name: "@hasna/example", version: "0.1.0" }));
      writeFileSync(join(packDir, "index.js"), "registerCloudTools();\n");
      execFileSync("tar", ["-czf", tarball, "-C", parent, "hasna-example-0.1.0"]);
      const result = runContracts(["no-cloud-scan", "--json", tarball]);
      expect(result.exitCode).toBe(1);
      const payload = parseStdoutJson(result);
      expect(payload.findings.some((finding: { path: string; pattern: string }) => finding.path === "index.js" && finding.pattern === "registerCloudTools")).toBe(true);
    } finally {
      rmSync(parent, { recursive: true, force: true });
      rmSync(outDir, { recursive: true, force: true });
    }
  });

  test("fails no-cloud scan on malformed package manifests", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    try {
      writeFileSync(join(dir, "package.json"), "{");
      const result = runContracts(["no-cloud-scan", "--json", dir]);
      expect(result.exitCode).toBe(1);
      const payload = parseStdoutJson(result);
      expect(payload.findings.some((finding: { pattern: string; message: string }) => finding.pattern === "package.json" && finding.message.includes("valid JSON object"))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("fails no-cloud scan when package manifest is missing", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    const packDir = mkdtempSync(join(tmpdir(), "contracts-pack-"));
    const tarball = join(packDir, "missing-package.tgz");
    try {
      writeFileSync(join(dir, "index.js"), "export const ok = true;\n");
      const result = runContracts(["no-cloud-scan", "--json", dir]);
      expect(result.exitCode).toBe(1);
      const payload = parseStdoutJson(result);
      expect(payload.findings.some((finding: { id: string }) => finding.id === "finding_package_manifest_missing")).toBe(true);

      execFileSync("tar", ["-czf", tarball, "-C", dir, "."]);
      const tarResult = runContracts(["no-cloud-scan", "--json", tarball]);
      expect(tarResult.exitCode).toBe(1);
      expect(parseStdoutJson(tarResult).findings.some((finding: { id: string }) => finding.id === "finding_package_manifest_missing")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(packDir, { recursive: true, force: true });
    }
  });

  test("fails no-cloud scan on invalid or mismatched app cloud manifests", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    try {
      const nullManifestPath = join(dir, "null-manifest.json");
      const mismatchManifestPath = join(dir, "mismatch-manifest.json");
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@hasna/example", version: "0.1.0" }));
      writeFileSync(nullManifestPath, "null");
      writeFileSync(
        mismatchManifestPath,
        JSON.stringify({
          schema: "hasna.app_cloud_manifest.v1",
          id: "cloud_manifest_mismatch",
          createdAt: "2026-06-28T20:10:00.000Z",
          packageName: "@hasna/other",
          appId: "other",
          storageMode: "app_owned_cloud",
          cloudBoundary: "app_owned",
          cloudResources: [
            {
              id: "other-db",
              provider: "aws",
              kind: "database",
              ownerPackage: "@hasna/other"
            }
          ],
          forbiddenSharedRuntimes: ["@hasna/cloud", "open-cloud"],
          dependencies: ["zod"]
        })
      );

      const nullResult = runContracts(["no-cloud-scan", "--json", "--manifest", nullManifestPath, dir]);
      expect(nullResult.exitCode).toBe(1);
      expect(parseStdoutJson(nullResult).findings.some((finding: { id: string }) => finding.id === "finding_app_cloud_manifest_invalid")).toBe(true);

      const mismatchResult = runContracts(["no-cloud-scan", "--json", "--manifest", mismatchManifestPath, dir]);
      expect(mismatchResult.exitCode).toBe(1);
      expect(parseStdoutJson(mismatchResult).findings.some((finding: { id: string }) => finding.id === "finding_app_cloud_manifest_package_mismatch")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("prefers root package metadata when nested package manifests exist", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    try {
      mkdirSync(join(dir, "src"));
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@hasna/root", version: "1.0.0" }));
      writeFileSync(join(dir, "src", "package.json"), JSON.stringify({ name: "@hasna/nested", version: "1.0.0" }));
      const result = runContracts(["no-cloud-scan", "--json", dir]);
      expect(result.exitCode).toBe(0);
      const payload = parseStdoutJson(result);
      expect(payload.packageName).toBe("@hasna/root");
      expect(payload.subject.uri).toBe("repo://@hasna/root");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("scans this package without treating scanner declarations as runtime edges", () => {
    const result = runContracts(["no-cloud-scan", "--json", "."]);
    expect(result.exitCode).toBe(0);
    const payload = parseStdoutJson(result);
    expect(payload.verdict).toBe("passed");
    expect(JSON.stringify(payload)).not.toContain(import.meta.dir);
  });

  test("allows only exact generated contracts declaration bundles to skip runtime edge scanning", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    const declarationText =
      "const markerA = 'FORBIDDEN_SHARED_CLOUD_RUNTIMES';\n" +
      "const markerB = 'hasna.no_cloud_evidence_pack.v1';\n" +
      "const runtime = '@hasna/cloud';\n";
    try {
      mkdirSync(join(dir, "dist"));
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@hasna/contracts", version: "0.4.1" }));
      writeFileSync(join(dir, "dist", "mode.js"), declarationText);
      writeFileSync(join(dir, "dist", "service-contract.js"), declarationText);
      writeFileSync(join(dir, "dist", "conformance.js"), declarationText);

      const result = runContracts(["no-cloud-scan", "--json", dir]);
      expect(result.exitCode).toBe(0);
      expect(parseStdoutJson(result).verdict).toBe("passed");

      writeFileSync(join(dir, "dist", "other.js"), declarationText);
      const invalidResult = runContracts(["no-cloud-scan", "--json", dir]);
      expect(invalidResult.exitCode).toBe(1);
      const payload = parseStdoutJson(invalidResult);
      expect(payload.findings.some((finding: { path: string; pattern: string }) => finding.path === "dist/other.js" && finding.pattern === "@hasna/cloud")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("does not allow downstream files to bypass scanning with declaration markers", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    try {
      mkdirSync(join(dir, "src"));
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@hasna/downstream", version: "0.1.0" }));
      writeFileSync(
        join(dir, "src", "schemas.ts"),
        "const markerA = 'FORBIDDEN_SHARED_CLOUD_RUNTIMES';\nconst markerB = 'hasna.no_cloud_evidence_pack.v1';\nregisterCloudTools();\n"
      );
      const result = runContracts(["no-cloud-scan", "--json", dir]);
      expect(result.exitCode).toBe(1);
      const payload = parseStdoutJson(result);
      expect(payload.findings.some((finding: { path: string; pattern: string }) => finding.path === "src/schemas.ts" && finding.pattern === "registerCloudTools")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
