import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  archivePackageEntries,
  auditExtractedPackage,
} from "../../src/testing/packed-consumer.js";

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
