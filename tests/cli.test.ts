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
    expect(result.stdout.toString()).toContain("hasna.secure_local_store_policy.v1");
  });

  test("prints secure local-store policy JSON", () => {
    const result = runContracts(["secure-local-store", "--json", "--store", "todos"]);
    expect(result.exitCode).toBe(0);
    const payload = parseStdoutJson(result);
    expect(payload.schema).toBe("hasna.secure_local_store_policy.v1");
    expect(payload.stores.map((store: { storeId: string }) => store.storeId)).toEqual(["todos"]);
    expect(payload.defaults.dryRunDefault).toBe(true);
  });

  test("reports unknown secure local-store ids without a stack trace", () => {
    const result = runContracts(["secure-local-store", "--json", "--store", "missing-store"]);
    expect(result.exitCode).toBe(2);
    const payload = parseStdoutJson(result);
    expect(payload.ok).toBe(false);
    expect(payload.code).toBe("secure_local_store_error");
    expect(payload.error).toContain("Unknown secure local store id");
    expect(result.stderr.toString()).toBe("");
  });

  test("rejects removed secure local-store execution flags", () => {
    for (const flag of [
      "--plan",
      "--apply",
      "--retention",
      "--sqlite-maintenance"
    ]) {
      const result = runContracts(["secure-local-store", "--json", flag]);
      expect(result.exitCode).not.toBe(0);
      const payload = parseStdoutJson(result);
      expect(payload.ok).toBe(false);
      expect(payload.code).toBe("commander.unknownOption");
      expect(result.stderr.toString()).toBe("");
    }
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
      // Imported from the retired runtime — the binding, not the bare name, is the breach.
      writeFileSync(join(dir, "index.js"), "import { registerCloudTools } from '@hasna/cloud';\nregisterCloudTools();\n");
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
      writeFileSync(join(dir, "index.js"), "import { registerCloudCommands } from '@hasna/cloud';\nregisterCloudCommands();\n");
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
      writeFileSync(join(packDir, "index.js"), "import { registerCloudTools } from '@hasna/cloud';\nregisterCloudTools();\n");
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

  test("allows vendored contracts denylist declarations in built and packed consumer output", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    const packParent = mkdtempSync(join(tmpdir(), "contracts-pack-parent-"));
    const packageDir = join(packParent, "package");
    const outDir = mkdtempSync(join(tmpdir(), "contracts-pack-out-"));
    const tarball = join(outDir, "hasna-example-0.1.0.tgz");
    const bundledDeclaration = 'var FORBIDDEN_SHARED_CLOUD_RUNTIMES = ["@hasna/cloud","open-cloud"];\n';
    try {
      for (const root of [dir, packageDir]) {
        mkdirSync(join(root, "dist"), { recursive: true });
        writeFileSync(join(root, "package.json"), JSON.stringify({ name: "@hasna/example", version: "0.1.0" }));
        writeFileSync(join(root, "dist", "index.js"), bundledDeclaration);
      }

      const result = runContracts(["no-cloud-scan", "--json", dir]);
      expect(result.exitCode).toBe(0);
      const payload = parseStdoutJson(result);
      expect(payload.verdict).toBe("passed");
      expect(payload.checks.find((check: { id: string }) => check.id === "source_runtime")).toMatchObject({
        kind: "source_import",
        status: "succeeded"
      });

      execFileSync("tar", ["-czf", tarball, "-C", packParent, "package"]);
      const packedResult = runContracts(["no-cloud-scan", "--json", tarball]);
      expect(packedResult.exitCode).toBe(0);
      const packedPayload = parseStdoutJson(packedResult);
      expect(packedPayload.verdict).toBe("passed");
      expect(packedPayload.checks.find((check: { id: string }) => check.id === "source_runtime")).toMatchObject({
        kind: "packed_artifact",
        status: "succeeded"
      });

      writeFileSync(
        join(dir, "dist", "index.js"),
        'var FORBIDDEN_SHARED_CLOUD_RUNTIMES = ["@hasna/cloud","consumer-runtime"];\n'
      );
      const nearMatchResult = runContracts(["no-cloud-scan", "--json", dir]);
      expect(nearMatchResult.exitCode).toBe(1);
      expect(
        parseStdoutJson(nearMatchResult).findings.some(
          (finding: { path: string; kind: string; severity: string; pattern: string }) =>
            finding.path === "dist/index.js" &&
            finding.kind === "source_import" &&
            finding.severity === "high" &&
            finding.pattern === "@hasna/cloud"
        )
      ).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(packParent, { recursive: true, force: true });
      rmSync(outDir, { recursive: true, force: true });
    }
  });

  test("still rejects bundled imports beside vendored contracts denylist declarations", () => {
    const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-"));
    const packParent = mkdtempSync(join(tmpdir(), "contracts-pack-parent-"));
    const packageDir = join(packParent, "package");
    const outDir = mkdtempSync(join(tmpdir(), "contracts-pack-out-"));
    const tarball = join(outDir, "hasna-example-0.1.0.tgz");
    const bundledImport =
      'var FORBIDDEN_SHARED_CLOUD_RUNTIMES = ["@hasna/cloud","open-cloud"];var cloud = require("@hasna/cloud");\n' +
      "cloud.registerCloudTools();\n";
    try {
      for (const root of [dir, packageDir]) {
        mkdirSync(join(root, "dist"), { recursive: true });
        writeFileSync(join(root, "package.json"), JSON.stringify({ name: "@hasna/example", version: "0.1.0" }));
        writeFileSync(join(root, "dist", "index.js"), bundledImport);
        writeFileSync(
          join(root, "dist", "chained.js"),
          'var FORBIDDEN_SHARED_CLOUD_RUNTIMES = ["@hasna/cloud","open-cloud"].map((name) => require(name));\n'
        );
      }

      const result = runContracts(["no-cloud-scan", "--json", dir]);
      expect(result.exitCode).toBe(1);
      const findings = parseStdoutJson(result).findings;
      expect(
        findings.some(
          (finding: { path: string; kind: string; severity: string; pattern: string; message: string }) =>
            finding.path === "dist/index.js" &&
            finding.kind === "source_import" &&
            finding.severity === "high" &&
            finding.pattern === "@hasna/cloud" &&
            finding.message.includes("module import")
          )
      ).toBe(true);
      expect(
        findings.some(
          (finding: { path: string; kind: string; severity: string; pattern: string }) =>
            finding.path === "dist/chained.js" &&
            finding.kind === "source_import" &&
            finding.severity === "high" &&
            finding.pattern === "@hasna/cloud"
        )
      ).toBe(true);

      execFileSync("tar", ["-czf", tarball, "-C", packParent, "package"]);
      const packedResult = runContracts(["no-cloud-scan", "--json", tarball]);
      expect(packedResult.exitCode).toBe(1);
      const packedFindings = parseStdoutJson(packedResult).findings;
      expect(
        packedFindings.some(
          (finding: { path: string; kind: string; severity: string; pattern: string; message: string }) =>
            finding.path === "dist/index.js" &&
            finding.kind === "packed_artifact" &&
            finding.severity === "critical" &&
            finding.pattern === "@hasna/cloud" &&
            finding.message.includes("module import")
          )
      ).toBe(true);
      expect(
        packedFindings.some(
          (finding: { path: string; kind: string; severity: string; pattern: string }) =>
            finding.path === "dist/chained.js" &&
            finding.kind === "packed_artifact" &&
            finding.severity === "critical" &&
            finding.pattern === "@hasna/cloud"
        )
      ).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(packParent, { recursive: true, force: true });
      rmSync(outDir, { recursive: true, force: true });
    }
  });

  /**
   * The vendored-denylist exemption, pinned SHAPE BY SHAPE.
   *
   * Keying the exemption on the identifier `FORBIDDEN_SHARED_CLOUD_RUNTIMES`
   * with a `const|let|var` prefix looked right and recognised almost nothing a
   * bundler emits — `__esm` hoists the declaration to a bare assignment and
   * `--minify-identifiers` renames it into a comma sequence. Both of those real
   * shapes are `accepts` rows below, so narrowing back to a keyword or a name
   * fails here rather than in a consumer's CI.
   *
   * Every `rejects` row is a mutation trap for one clause of the exemption:
   * drop the length check and `shorter-array` flips; drop the ordered `every`
   * and `reversed-order` flips; drop the `=` and `object-property` /
   * `call-argument` flip; drop the trailing `.`/`(`/`[` lookahead and
   * `chained-require` / `indexed-load` flip; drop the build-output path scope
   * and `authored-src` / `authored-lib` flip; widen the mask past the first `]`
   * and `two-arrays-one-line` flips; blank the whole file instead of the span
   * and `mention-elsewhere` / `config-env` flip.
   */
  const vendoredDenylistShapes: {
    name: string;
    accepts: boolean;
    files: Record<string, string>;
    findings?: { path: string; pattern: string; reason: string }[];
  }[] = [
    {
      name: "accepts: bun __esm hoists the declaration to a bare assignment",
      accepts: true,
      files: {
        "dist/index.js":
          "var FORBIDDEN_SHARED_CLOUD_RUNTIMES;\nvar init_schemas = __esm(() => {\n  FORBIDDEN_SHARED_CLOUD_RUNTIMES = [\"@hasna/cloud\", \"open-cloud\"];\n});\n"
      }
    },
    {
      name: "accepts: --minify-identifiers renames it into a comma sequence",
      accepts: true,
      files: { "dist/index.js": 'var Sk=x.strict(),Ob=["@hasna/cloud","open-cloud"],pG=b.enum(["aws","gcp"]),qq=1;\n' }
    },
    {
      name: "accepts: exported const in an esm bundle",
      accepts: true,
      files: { "dist/index.js": 'export const FORBIDDEN_SHARED_CLOUD_RUNTIMES = ["@hasna/cloud", "open-cloud"];\n' }
    },
    {
      name: "accepts: single-quoted elements",
      accepts: true,
      files: { "dist/index.js": "var names = ['@hasna/cloud', 'open-cloud'];\n" }
    },
    {
      name: "accepts: no trailing semicolon",
      accepts: true,
      files: { "dist/index.js": 'var names = ["@hasna/cloud", "open-cloud"]\n' }
    },
    {
      name: "accepts: emitted into bin/ rather than dist/",
      accepts: true,
      files: { "bin/cli.js": 'var q=["@hasna/cloud","open-cloud"],z=2;\n' }
    },
    {
      name: "rejects: authored src cannot exempt itself and load through the array",
      accepts: false,
      files: {
        "src/loader.ts":
          'const FORBIDDEN_SHARED_CLOUD_RUNTIMES = ["@hasna/cloud", "open-cloud"];\nexport async function load() {\n  await import(FORBIDDEN_SHARED_CLOUD_RUNTIMES[0]!);\n  return require(FORBIDDEN_SHARED_CLOUD_RUNTIMES[1]!);\n}\n'
      },
      findings: [
        { path: "src/loader.ts", pattern: "@hasna/cloud", reason: "source reference" },
        { path: "src/loader.ts", pattern: "open-cloud", reason: "source reference" }
      ]
    },
    {
      name: "rejects: a folder named dist UNDER src is a folder somebody named",
      accepts: false,
      files: {
        "src/dist/loader.ts": 'const NAMES = ["@hasna/cloud", "open-cloud"];\nexport const load = () => import(NAMES[0]!);\n'
      },
      findings: [
        { path: "src/dist/loader.ts", pattern: "@hasna/cloud", reason: "source reference" },
        { path: "src/dist/loader.ts", pattern: "open-cloud", reason: "source reference" }
      ]
    },
    {
      name: "accepts: authored-looking structure UNDER build output is still output",
      accepts: true,
      files: { "dist/src/index.js": 'var names = ["@hasna/cloud", "open-cloud"];\n' }
    },
    {
      name: "accepts: build output nested in a monorepo package",
      accepts: true,
      files: { "packages/consumer/dist/index.js": 'var names = ["@hasna/cloud", "open-cloud"];\n' }
    },
    {
      name: "rejects: lib/ is authored in real repos, not build output",
      accepts: false,
      files: { "lib/names.ts": 'const names = ["@hasna/cloud", "open-cloud"];\nexport const first = names[0];\n' },
      findings: [
        { path: "lib/names.ts", pattern: "@hasna/cloud", reason: "source reference" },
        { path: "lib/names.ts", pattern: "open-cloud", reason: "source reference" }
      ]
    },
    {
      name: "rejects: the literal is invoked on, which turns it into a load",
      accepts: false,
      files: { "dist/chained.js": 'var mods = ["@hasna/cloud", "open-cloud"].map((name) => require(name));\n' },
      findings: [
        { path: "dist/chained.js", pattern: "@hasna/cloud", reason: "source reference" },
        { path: "dist/chained.js", pattern: "open-cloud", reason: "source reference" }
      ]
    },
    {
      name: "rejects: the literal is indexed and the element loaded",
      accepts: false,
      files: { "dist/idx.js": 'var first = ["@hasna/cloud", "open-cloud"][0];\nrequire(first);\n' },
      findings: [
        { path: "dist/idx.js", pattern: "@hasna/cloud", reason: "source reference" },
        { path: "dist/idx.js", pattern: "open-cloud", reason: "source reference" }
      ]
    },
    {
      name: "rejects: passed straight into a call rather than stored",
      accepts: false,
      files: { "dist/arg.js": 'loadAll(["@hasna/cloud", "open-cloud"]);\n' },
      findings: [
        { path: "dist/arg.js", pattern: "@hasna/cloud", reason: "source reference" },
        { path: "dist/arg.js", pattern: "open-cloud", reason: "source reference" }
      ]
    },
    {
      name: "rejects: an object property is not an assignment",
      accepts: false,
      files: { "dist/index.js": 'var schema = { forbidden: ["@hasna/cloud", "open-cloud"] };\n' },
      findings: [
        { path: "dist/index.js", pattern: "@hasna/cloud", reason: "source reference" },
        { path: "dist/index.js", pattern: "open-cloud", reason: "source reference" }
      ]
    },
    {
      name: "rejects: a shorter array is the consumer's own list",
      accepts: false,
      files: { "dist/index.js": 'var names = ["@hasna/cloud"];\n' },
      findings: [{ path: "dist/index.js", pattern: "@hasna/cloud", reason: "source reference" }]
    },
    {
      name: "rejects: the same two names in the other order",
      accepts: false,
      files: { "dist/index.js": 'var names = ["open-cloud", "@hasna/cloud"];\n' },
      findings: [
        { path: "dist/index.js", pattern: "@hasna/cloud", reason: "source reference" },
        { path: "dist/index.js", pattern: "open-cloud", reason: "source reference" }
      ]
    },
    {
      name: "rejects: a superset that also names a third forbidden runtime",
      accepts: false,
      files: { "dist/index.js": 'var names = ["@hasna/cloud", "open-cloud", "cloud-mcp"];\n' },
      findings: [
        { path: "dist/index.js", pattern: "@hasna/cloud", reason: "source reference" },
        { path: "dist/index.js", pattern: "open-cloud", reason: "source reference" },
        { path: "dist/index.js", pattern: "cloud-mcp", reason: "source reference" }
      ]
    },
    {
      name: "rejects: a second array on the same line the mask must not reach",
      accepts: false,
      files: { "dist/index.js": 'var a = ["@hasna/cloud", "open-cloud"], b = ["open-cloud", "other"];\n' },
      findings: [{ path: "dist/index.js", pattern: "open-cloud", reason: "source reference" }]
    },
    {
      name: "rejects: a bare mention elsewhere in the same build-output file",
      accepts: false,
      files: {
        "dist/index.js": 'var a = ["@hasna/cloud", "open-cloud"];\nvar registry = { legacy: "open-cloud" };\n'
      },
      findings: [{ path: "dist/index.js", pattern: "open-cloud", reason: "source reference" }]
    },
    {
      name: "rejects: runtime config in build output is still config",
      accepts: false,
      files: { "dist/index.js": 'var a = ["@hasna/cloud", "open-cloud"];\nprocess.env.HASNA_CLOUD_URL;\n' },
      findings: [{ path: "dist/index.js", pattern: "HASNA_CLOUD_", reason: "source reference" }]
    },
    {
      name: "rejects: a TOML array under dist/ is config a person wrote, not emit",
      accepts: false,
      files: { "dist/settings.toml": 'forbidden = ["@hasna/cloud", "open-cloud"]\n' },
      findings: [
        { path: "dist/settings.toml", pattern: "@hasna/cloud", reason: "source reference" },
        { path: "dist/settings.toml", pattern: "open-cloud", reason: "source reference" }
      ]
    },
    {
      name: "rejects: an externalised import that survived bundling",
      accepts: false,
      files: {
        "dist/index.js": 'import { connect } from "@hasna/cloud";\nvar a = ["@hasna/cloud", "open-cloud"];\n'
      },
      findings: [{ path: "dist/index.js", pattern: "@hasna/cloud", reason: "module import" }]
    }
  ];

  for (const shape of vendoredDenylistShapes) {
    test(`vendored contracts denylist — ${shape.name}`, () => {
      const dir = mkdtempSync(join(tmpdir(), "contracts-no-cloud-shape-"));
      try {
        writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@hasna/consumer-example", version: "0.1.0" }));
        for (const [rel, contents] of Object.entries(shape.files)) {
          const full = join(dir, rel);
          mkdirSync(full.slice(0, full.lastIndexOf("/")), { recursive: true });
          writeFileSync(full, contents);
        }

        const result = runContracts(["no-cloud-scan", "--json", dir]);
        const payload = parseStdoutJson(result);
        const findings = payload.findings as {
          path: string;
          kind: string;
          severity: string;
          pattern: string;
          message: string;
        }[];

        if (shape.accepts) {
          expect(result.exitCode).toBe(0);
          expect(payload.verdict).toBe("passed");
          expect(findings).toEqual([]);
          return;
        }

        expect(result.exitCode).toBe(1);
        expect(payload.verdict).toBe("failed");
        for (const expected of shape.findings ?? []) {
          expect(
            findings.some(
              (finding) =>
                finding.path === expected.path &&
                finding.kind === "source_import" &&
                finding.severity === "high" &&
                finding.pattern === expected.pattern &&
                finding.message.endsWith(`(${expected.reason})`)
            )
          ).toBe(true);
        }
        // Nothing beyond the named findings, so a widened match cannot hide here.
        expect(findings.length).toBe((shape.findings ?? []).length);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }

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
      writeFileSync(join(dir, "dist", "secure-local-store.js"), declarationText);
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
        "const markerA = 'FORBIDDEN_SHARED_CLOUD_RUNTIMES';\nconst markerB = 'hasna.no_cloud_evidence_pack.v1';\n" +
          "import { registerCloudTools } from '@hasna/cloud';\nregisterCloudTools();\n"
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
