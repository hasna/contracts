import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const repoRoot = join(import.meta.dir, "..");

describe("execution-free Contracts boundary", () => {
  test("secure-local-store remains declarative and cannot inspect or mutate operator state", () => {
    const source = readFileSync(join(repoRoot, "src", "secure-local-store.ts"), "utf8");

    for (const forbidden of [
      /from\s+["']node:fs["']/,
      /from\s+["']node:os["']/,
      /import\(["']bun:sqlite["']\)/,
      /\bchmodSync\b/,
      /\brmSync\b/,
      /\blstatSync\b/,
      /\breaddirSync\b/,
      /\bplanSecureLocalStoreLifecycle\b/,
      /\bapplySecureLocalStorePlan\b/,
      /\bPRAGMA\b/,
      /\bVACUUM\b/
    ]) {
      expect(source).not.toMatch(forbidden);
    }
  });

  test("the CLI can print policy but exposes no plan, apply, retention, or SQLite execution flags", () => {
    const source = readFileSync(join(repoRoot, "src", "cli", "index.ts"), "utf8");

    for (const forbidden of [
      /--plan/,
      /--apply/,
      /--retention/,
      /--sqlite-maintenance/,
      /\bplanSecureLocalStoreLifecycle\b/,
      /\bapplySecureLocalStorePlan\b/
    ]) {
      expect(source).not.toMatch(forbidden);
    }
  });
});
