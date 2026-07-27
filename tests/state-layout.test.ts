import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { KIT_MANIFEST_FILE, KIT_TARGET_SUBDIR } from "../src/kit/generate";
import { ProjectLayoutSchema } from "../src/schemas";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const legacyGlobalPaths = ["~/.contracts", "~/.open-contracts"];
const legacyGlobalSegments = [".contracts", ".open-contracts"];

function runtimeFiles(path: string): string[] {
  if (!existsSync(path)) return [];
  if (!statSync(path).isDirectory()) return [path];
  return readdirSync(path, { withFileTypes: true }).flatMap((entry) =>
    runtimeFiles(join(path, entry.name))
  );
}

describe("@hasna/contracts state layout", () => {
  test("does not read legacy package-global dotdirs", () => {
    const files = [
      ...runtimeFiles(join(root, "src")),
      ...runtimeFiles(join(root, "scripts")),
      join(root, "package.json"),
    ].filter((path) => /\.(?:json|mjs|ts)$/.test(path));

    for (const path of files) {
      const source = readFileSync(path, "utf8");
      for (const legacySegment of legacyGlobalSegments) {
        expect(source, `${path} must not read a ${legacySegment} home entry`).not.toContain(
          legacySegment
        );
      }
    }

    const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
      scripts?: Record<string, string>;
    };
    expect(packageJson.scripts?.postinstall).toBeUndefined();
  });

  test("keeps the intentional outputs project-relative", () => {
    const layout = ProjectLayoutSchema.parse({});
    expect(layout.schemaRoot).toBe(".hasna/project");
    expect(layout.dashboardManifest).toBe(".hasna/project/dashboard.render.json");
    expect(KIT_TARGET_SUBDIR).toBe("src/generated/storage-kit");
    expect(KIT_MANIFEST_FILE).toBe(".storage-kit-manifest.json");
  });

  test("documents the audited global and project-local path policy", () => {
    const policyPath = join(root, "docs", "STATE_LAYOUT.md");
    expect(existsSync(policyPath)).toBe(true);
    if (!existsSync(policyPath)) return;

    const policy = readFileSync(policyPath, "utf8");
    expect(policy).toContain("~/.hasna/contracts");
    for (const legacyPath of legacyGlobalPaths) {
      expect(policy).toContain(legacyPath);
    }
    expect(policy).toContain(".hasna/project");
    expect(policy).toContain("src/generated/storage-kit/.storage-kit-manifest.json");

    const readme = readFileSync(join(root, "README.md"), "utf8");
    expect(readme).toContain("docs/STATE_LAYOUT.md");
  });
});
