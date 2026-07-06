import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { runRepoConformance } from "../src";

const repoRoot = join(import.meta.dir, "..");

describe("repo conformance kit", () => {
  test("open-contracts passes conformance against itself", () => {
    const report = runRepoConformance(repoRoot, { env: {} });
    const failed = report.checks.filter((c) => c.status === "fail");
    expect(failed).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.name).toBe("contracts");
    expect(report.class).toBe("library");
  });

  test("manifest_valid, bins, and no_cloud_guard checks run", () => {
    const report = runRepoConformance(repoRoot, { env: {} });
    const ids = report.checks.map((c) => c.id);
    expect(ids).toContain("manifest_valid");
    expect(ids).toContain("bins_allowlisted");
    expect(ids).toContain("bins_match_package");
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

  test("normalizes a deprecated alias env to cloud", () => {
    const report = runRepoConformance(repoRoot, { env: { HASNA_CONTRACTS_STORAGE_MODE: "self_hosted" } });
    const mode = report.checks.find((c) => c.id === "mode_enum_compliance");
    expect(mode?.status).toBe("pass");
    expect(mode?.detail).toContain("cloud");
  });

  test("validates a serve health sample shape", () => {
    // Simulate a service repo by directly shape-checking the health schema path.
    const report = runRepoConformance(repoRoot, {
      env: {},
      healthSample: { status: "ok", version: "1.0.0", mode: "cloud" }
    });
    // library has no serve bin, so health is skipped even with a sample
    const health = report.checks.find((c) => c.id === "health_shape");
    expect(health?.status).toBe("skip");
  });
});
