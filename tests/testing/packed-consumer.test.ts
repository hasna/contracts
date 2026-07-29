import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  archivePackageEntries,
  auditExtractedPackage,
  installPackedConsumerFromArchive,
  isEnvironmentRestrictedInstall,
  PACK_INSTALL_DENY_ENV,
  PACK_INSTALL_FALLBACK_ENV,
  packInstallDenied,
  packInstallFallbackAllowed,
} from "../../src/testing/packed-consumer.js";

const root = join(import.meta.dir, "..", "..");

const workspaces: string[] = [];

function workspace(): string {
  const directory = mkdtempSync(join(tmpdir(), "contracts-packed-consumer-"));
  workspaces.push(directory);
  return directory;
}

afterEach(() => {
  while (workspaces.length > 0) {
    rmSync(workspaces.pop()!, { recursive: true, force: true });
  }
});

const archiveListing = [
  "package/",
  "package/package.json",
  "package/dist/",
  "package/dist/todos/index.js",
];

function faithfulTree(): string {
  const packageRoot = join(workspace(), "node_modules", "@hasna", "contracts");
  mkdirSync(join(packageRoot, "dist", "todos"), { recursive: true });
  writeFileSync(join(packageRoot, "package.json"), "{}", "utf8");
  writeFileSync(join(packageRoot, "dist", "todos", "index.js"), "export {};", "utf8");
  return packageRoot;
}

describe("archivePackageEntries", () => {
  test("keeps files under the package prefix and drops directory entries", () => {
    expect(archivePackageEntries(archiveListing)).toEqual([
      "dist/todos/index.js",
      "package.json",
    ]);
  });

  test("ignores entries outside the package prefix", () => {
    expect(archivePackageEntries(["other/file.js", "package/a.js"])).toEqual(["a.js"]);
  });
});

describe("auditExtractedPackage", () => {
  test("accepts a tree that matches the archive exactly", () => {
    const audit = auditExtractedPackage(faithfulTree(), archivePackageEntries(archiveListing));
    expect(audit).toEqual({ ok: true, failures: [] });
  });

  test("rejects a symlink that could reach back into the repo source tree", () => {
    const packageRoot = faithfulTree();
    symlinkSync(join(import.meta.dir, "..", "..", "src"), join(packageRoot, "src"));
    const audit = auditExtractedPackage(packageRoot, archivePackageEntries(archiveListing));
    expect(audit.ok).toBe(false);
    expect(audit.failures).toContain("extracted package contains a symlink: src");
  });

  test("rejects a package root that is itself a symlink", () => {
    const packageRoot = faithfulTree();
    const linked = join(workspace(), "linked-contracts");
    symlinkSync(packageRoot, linked);
    const audit = auditExtractedPackage(linked, archivePackageEntries(archiveListing));
    expect(audit).toEqual({
      ok: false,
      failures: ["extracted package root is a symlink"],
    });
  });

  test("rejects a tree carrying a file the archive does not ship", () => {
    const packageRoot = faithfulTree();
    mkdirSync(join(packageRoot, "src", "todos"), { recursive: true });
    writeFileSync(join(packageRoot, "src", "todos", "index.ts"), "export {};", "utf8");
    const audit = auditExtractedPackage(packageRoot, archivePackageEntries(archiveListing));
    expect(audit.ok).toBe(false);
    expect(audit.failures).toContain(
      "extracted package carries an entry the archive does not: src/todos/index.ts",
    );
  });

  test("rejects a tree missing an archive entry", () => {
    const packageRoot = faithfulTree();
    rmSync(join(packageRoot, "dist", "todos", "index.js"));
    const audit = auditExtractedPackage(packageRoot, archivePackageEntries(archiveListing));
    expect(audit.ok).toBe(false);
    expect(audit.failures).toContain(
      "extracted package is missing an archive entry: dist/todos/index.js",
    );
  });
});

describe("pack install policy", () => {
  test("the extraction opt-in is exact, not truthy", () => {
    expect(packInstallFallbackAllowed({ [PACK_INSTALL_FALLBACK_ENV]: "1" })).toBe(true);
    expect(packInstallFallbackAllowed({ [PACK_INSTALL_FALLBACK_ENV]: "true" })).toBe(false);
    expect(packInstallFallbackAllowed({ [PACK_INSTALL_FALLBACK_ENV]: "" })).toBe(false);
    expect(packInstallFallbackAllowed({})).toBe(false);
  });

  test("the deny seam is exact, not truthy", () => {
    expect(packInstallDenied({ [PACK_INSTALL_DENY_ENV]: "1" })).toBe(true);
    expect(packInstallDenied({ [PACK_INSTALL_DENY_ENV]: "0" })).toBe(false);
    expect(packInstallDenied({})).toBe(false);
  });

  test("recognises the failures an offline or read-only runner produces", () => {
    for (const output of [
      "error: ConnectionRefused downloading package manifest commander",
      "error: FailedToOpenSocket downloading package manifest zod",
      "error: ReadOnlyFileSystem installing zod",
    ]) {
      expect(isEnvironmentRestrictedInstall(output)).toBe(true);
    }
  });

  test("does not classify a dependency-resolution failure as an environment restriction", () => {
    // A package whose declared range cannot resolve must keep the loud install
    // failure — it is a defect in the package, not in the runner.
    expect(isEnvironmentRestrictedInstall("error: zod@^99.0.0 failed to resolve")).toBe(false);
  });
});

describe("installPackedConsumerFromArchive", () => {
  function packedFixture(packageFiles: Record<string, string>) {
    const base = workspace();
    const stage = join(base, "stage");
    for (const [relativePath, contents] of Object.entries(packageFiles)) {
      const absolute = join(stage, "package", relativePath);
      mkdirSync(join(absolute, ".."), { recursive: true });
      writeFileSync(absolute, contents, "utf8");
    }
    const archivePath = join(base, "fixture.tgz");
    const packed = Bun.spawnSync(["tar", "-czf", archivePath, "-C", stage, "package"], {
      stdout: "pipe",
      stderr: "pipe",
    });
    if (packed.exitCode !== 0) {
      throw new Error(new TextDecoder().decode(packed.stderr));
    }
    const listing = Bun.spawnSync(["tar", "-tzf", archivePath], { stdout: "pipe", stderr: "pipe" });
    if (listing.exitCode !== 0) {
      throw new Error(new TextDecoder().decode(listing.stderr));
    }
    const entries = new TextDecoder().decode(listing.stdout).split("\n").filter(Boolean);
    const consumerRoot = join(base, "consumer");
    mkdirSync(consumerRoot, { recursive: true });
    const repoRoot = join(base, "repo");
    mkdirSync(join(repoRoot, "node_modules", "fixture-dep"), { recursive: true });
    writeFileSync(
      join(repoRoot, "node_modules", "fixture-dep", "index.js"),
      "export {};",
      "utf8",
    );
    return { archivePath, entries, consumerRoot, repoRoot };
  }

  const shippedFiles = {
    "package.json": "{}",
    "dist/todos/index.js": "export {};",
  };

  test("extracts the archive and copies the runtime dependencies beside it", () => {
    const fixture = packedFixture(shippedFiles);
    const packageRoot = installPackedConsumerFromArchive({
      archivePath: fixture.archivePath,
      consumerRoot: fixture.consumerRoot,
      repoRoot: fixture.repoRoot,
      archiveEntries: fixture.entries,
      runtimeDependencies: ["fixture-dep"],
    });
    expect(packageRoot).toBe(
      join(fixture.consumerRoot, "node_modules", "@hasna", "contracts"),
    );
    expect(existsSync(join(packageRoot, "dist", "todos", "index.js"))).toBe(true);
    expect(
      existsSync(join(fixture.consumerRoot, "node_modules", "fixture-dep", "index.js")),
    ).toBe(true);
  });

  test("rejects a tree carrying a file the archive listing does not declare", () => {
    // The audit is the diagnostic path's only provenance proof — the symlink
    // check the `bun install` path relies on is tautological here — so it has
    // to be wired into the installer, not merely available beside it.
    const fixture = packedFixture({ ...shippedFiles, "src/todos/index.ts": "export {};" });
    expect(() => installPackedConsumerFromArchive({
      archivePath: fixture.archivePath,
      consumerRoot: fixture.consumerRoot,
      repoRoot: fixture.repoRoot,
      archiveEntries: fixture.entries.filter((entry) => entry !== "package/src/todos/index.ts"),
      runtimeDependencies: [],
    })).toThrow(/carries an entry the archive does not: src\/todos\/index\.ts/);
  });

  test("rejects a tree missing a file the archive listing declares", () => {
    const fixture = packedFixture(shippedFiles);
    expect(() => installPackedConsumerFromArchive({
      archivePath: fixture.archivePath,
      consumerRoot: fixture.consumerRoot,
      repoRoot: fixture.repoRoot,
      archiveEntries: [...fixture.entries, "package/generated/todos/v1/contract.json"],
      runtimeDependencies: [],
    })).toThrow(/missing an archive entry: generated\/todos\/v1\/contract\.json/);
  });
});

// The publish gate (`smoke:todos-pack`, run by `verify:release`, which is
// `prepack` and `prepublishOnly`) must never print "isolated Todos consumer
// passed" on a run that could not resolve the packed package the way a real
// consumer does. Only `bun install` proves the declared dependency ranges are
// installable; an archive extraction proves nothing about them. These cases
// drive the real script, so the guarantee is asserted on the artifact that
// actually gates npm. The deny seam stands in for an offline runner because it
// is answered before the archive is packed, which keeps the refusal observable
// during `verify:release`, where `bun test` runs before `bun run build`.
describe("scripts/smoke-todos-pack.ts publish gate", () => {
  function runPackSmoke(env: Record<string, string>) {
    const result = Bun.spawnSync(["bun", "scripts/smoke-todos-pack.ts"], {
      cwd: root,
      env: { ...process.env, ...env },
      stdout: "pipe",
      stderr: "pipe",
    });
    return {
      exitCode: result.exitCode,
      stdout: new TextDecoder().decode(result.stdout),
      stderr: new TextDecoder().decode(result.stderr),
    };
  }

  test("refuses to run when an isolated install is unavailable", () => {
    const result = runPackSmoke({
      [PACK_INSTALL_DENY_ENV]: "1",
      [PACK_INSTALL_FALLBACK_ENV]: "",
    });
    expect(result.stdout).not.toContain("isolated Todos consumer passed");
    expect(result.exitCode).toBe(1);
    expect(`${result.stdout}${result.stderr}`).toContain(
      "could not run an isolated `bun install`",
    );
    expect(`${result.stdout}${result.stderr}`).toContain("fail-closed");
  });

  test("reports UNVERIFIED instead of passing when the extraction opt-in is set", () => {
    const result = runPackSmoke({
      [PACK_INSTALL_DENY_ENV]: "1",
      [PACK_INSTALL_FALLBACK_ENV]: "1",
    });
    expect(result.stdout).not.toContain("isolated Todos consumer passed");
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("todos pack smoke UNVERIFIED");
  });
});
