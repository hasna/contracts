import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import { CONTRACTS_PACKAGE_VERSION } from "../src/schemas.js";

const root = join(import.meta.dir, "..");
const expectedUnreleasedVersion = "0.5.3";
const forbiddenInternalDomains = [["hasna", "xyz"].join(".")];

function commandText(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function run(command: string[], cwd = root): string {
  const result = Bun.spawnSync(command, {
    cwd,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) {
    throw new Error(
      `${command.join(" ")} exited ${result.exitCode}\nstdout:\n${commandText(result.stdout)}\nstderr:\n${commandText(result.stderr)}`,
    );
  }
  return commandText(result.stdout).trim();
}

function collectFiles(target: string): string[] {
  const stat = lstatSync(target);
  if (stat.isSymbolicLink()) return [];
  if (stat.isFile()) return [target];
  if (!stat.isDirectory()) return [];
  return readdirSync(target, { withFileTypes: true }).flatMap((entry) =>
    collectFiles(join(target, entry.name)),
  );
}

function trackedFiles(): string[] {
  const result = Bun.spawnSync(["git", "ls-files", "-z"], {
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) {
    throw new Error(`git ls-files failed: ${commandText(result.stderr)}`);
  }
  return commandText(result.stdout).split("\0").filter(Boolean);
}

function findForbiddenInternalDomains(scanRoot: string, targets: string[]): string[] {
  const needles = forbiddenInternalDomains.map((domain) => domain.toLowerCase());
  return targets
    .flatMap((target) => collectFiles(join(scanRoot, target)))
    .filter((file) => {
      const contents = readFileSync(file, "utf8").toLowerCase();
      return needles.some((needle) => contents.includes(needle));
    })
    .map((file) => relative(scanRoot, file))
    .sort();
}

describe("published package hostname and provenance boundary", () => {
  let temporaryRoot = "";
  let extractedPackageRoot = "";

  beforeAll(() => {
    temporaryRoot = mkdtempSync(join(tmpdir(), "contracts-package-security-"));
    const extracted = join(temporaryRoot, "extracted");
    mkdirSync(extracted);

    run(["bun", "run", "build"]);
    const packedFilename = run([
      "bun",
      "pm",
      "pack",
      "--destination",
      temporaryRoot,
      "--ignore-scripts",
      "--quiet",
    ]);
    const archive = isAbsolute(packedFilename)
      ? packedFilename
      : join(temporaryRoot, packedFilename);
    run(["tar", "-xzf", archive, "-C", extracted]);
    extractedPackageRoot = join(extracted, "package");
  });

  afterAll(() => {
    if (temporaryRoot) rmSync(temporaryRoot, { recursive: true, force: true });
  });

  test("scanner rejects a forbidden internal domain", () => {
    const fixtureRoot = join(temporaryRoot, "negative-control");
    mkdirSync(fixtureRoot);
    writeFileSync(join(fixtureRoot, "fixture.txt"), forbiddenInternalDomains[0]!.toUpperCase());
    expect(findForbiddenInternalDomains(fixtureRoot, ["."])).toEqual(["fixture.txt"]);
  });

  test("all tracked source, docs, tests, and examples contain no forbidden internal domains", () => {
    const findings = findForbiddenInternalDomains(root, trackedFiles());
    expect(findings).toEqual([]);
  });

  test("generated build output contains no forbidden internal domains", () => {
    expect(findForbiddenInternalDomains(root, ["dist"])).toEqual([]);
  });

  test("actual packed archive contents contain no forbidden internal domains", () => {
    expect(findForbiddenInternalDomains(extractedPackageRoot, ["."])).toEqual([]);
  });

  test("source, generated output, and packed package use the fresh unreleased version", async () => {
    const sourcePackage = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
      version: string;
    };
    const packedPackage = JSON.parse(
      readFileSync(join(extractedPackageRoot, "package.json"), "utf8"),
    ) as { version: string };
    const generated = (await import(
      `${pathToFileURL(join(root, "dist/schemas.js")).href}?source=${Date.now()}`
    )) as { CONTRACTS_PACKAGE_VERSION: string };
    const packedGenerated = (await import(
      `${pathToFileURL(join(extractedPackageRoot, "dist/schemas.js")).href}?packed=${Date.now()}`
    )) as { CONTRACTS_PACKAGE_VERSION: string };

    expect(sourcePackage.version).toBe(expectedUnreleasedVersion);
    expect(CONTRACTS_PACKAGE_VERSION).toBe(expectedUnreleasedVersion);
    expect(generated.CONTRACTS_PACKAGE_VERSION).toBe(expectedUnreleasedVersion);
    expect(packedPackage.version).toBe(expectedUnreleasedVersion);
    expect(packedGenerated.CONTRACTS_PACKAGE_VERSION).toBe(expectedUnreleasedVersion);
  });
});
