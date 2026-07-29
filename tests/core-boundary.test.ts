import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const root = join(import.meta.dir, "..");
const coreEntryPoints = ["src/index.ts", "src/schemas.ts", "src/validators.ts", "src/primitives.ts"];
const forbiddenImports = /["'](?:node:(?:fs|fs\/promises|os|net|http|https|child_process)|bun:sqlite|pg|commander)["']/;
const forbiddenRuntimeReads = /\b(?:process\.env|Bun\.(?:serve|spawn|spawnSync|write)|fetch\s*\()/;

function localImports(source: string): string[] {
  return [...source.matchAll(/(?:from\s+|import\s*\()["'](\.[^"']+)["']/g)]
    .map((match) => match[1]!)
    .filter((specifier) => !specifier.endsWith(".json"));
}

function coreImportGraph(): string[] {
  const pending = coreEntryPoints.map((file) => join(root, file));
  const seen = new Set<string>();
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    const source = readFileSync(file, "utf8");
    for (const specifier of localImports(source)) {
      const sourceSpecifier = specifier.endsWith(".js")
        ? specifier.replace(/\.js$/, ".ts")
        : `${specifier}.ts`;
      pending.push(resolve(join(file, ".."), sourceSpecifier));
    }
  }
  return [...seen].sort();
}

describe("side-effect-free published core", () => {
  test("the complete root import graph has no filesystem, environment, network, database, CLI, or codegen edges", () => {
    const graph = coreImportGraph();
    expect(graph.map((file) => file.slice(root.length + 1))).toEqual([
      "src/index.ts",
      "src/primitives.ts",
      "src/schemas.ts",
      "src/validators.ts",
    ]);
    for (const file of graph) {
      const source = readFileSync(file, "utf8");
      expect(source, file).not.toMatch(forbiddenImports);
      expect(source, file).not.toMatch(forbiddenRuntimeReads);
    }
  });

  test("the release manifest exports no executable legacy surface", () => {
    const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
      bin?: unknown;
      exports: Record<string, unknown>;
      files: string[];
    };
    expect(manifest.bin).toBeUndefined();
    for (const removed of [
      "./auth",
      "./client",
      "./client/storage",
      "./vendor-kit",
      "./sdk",
      "./todos",
      "./artifact-scan",
    ]) {
      expect(manifest.exports[removed], removed).toBeUndefined();
    }
    expect(JSON.stringify(manifest.files)).not.toMatch(/kit|todos|cli|docker/i);
  });

  test("runtime helpers have explicit package owners", () => {
    const owners = new Map([
      ["packages/auth/package.json", "@hasna/contracts-auth"],
      ["packages/cli/package.json", "@hasna/contracts-cli"],
      ["packages/client/package.json", "@hasna/contracts-client"],
      ["packages/vendor-kit/package.json", "@hasna/contracts-vendor-kit"],
      ["packages/sdk-generator/package.json", "@hasna/contracts-sdk-generator"],
    ]);
    for (const [path, name] of owners) {
      const manifest = JSON.parse(readFileSync(join(root, path), "utf8")) as { name: string };
      expect(manifest.name).toBe(name);
    }
  });
});
