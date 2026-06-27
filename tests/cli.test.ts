import { describe, expect, test } from "bun:test";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
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
});
