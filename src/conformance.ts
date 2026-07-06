// Repo self-conformance for the Hasna Service Contract v1.
//
// A repo runs this against its own root to prove it satisfies the contract:
//   1. hasna.contract.json is present and valid (manifest + class rules).
//   2. Declared bins match package.json `bin` and stay in the allowlist.
//   3. Env parsing follows the HASNA_<NAME>_STORAGE_MODE spec and any mode env
//      value normalizes to the local|cloud enum (mode enum compliance).
//   4. If a `<name>-serve` bin exists, the health payload (when sampled) has the
//      { status, version, mode } shape.
//   5. No forbidden shared cloud runtimes (reuses the no-cloud guard).

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { HealthResponseSchema, allowedBinsForName } from "./schemas";
import { loadServiceContractManifest, type LoadServiceContractResult } from "./service-contract";
import { normalizeStorageMode, storageEnvKeys, type Env } from "./mode";
import { scanNoCloudTarget } from "./no-cloud";

export type ConformanceStatus = "pass" | "fail" | "skip";

export interface ConformanceCheck {
  id: string;
  status: ConformanceStatus;
  detail: string;
}

export interface RepoConformanceReport {
  ok: boolean;
  repoRoot: string;
  name: string | null;
  class: string | null;
  checks: ConformanceCheck[];
}

export interface RepoConformanceOptions {
  /** Environment to parse for mode-enum compliance (defaults to process.env). */
  env?: Env;
  /** Optional sampled `GET /health` payload to shape-check. */
  healthSample?: unknown;
  /** Skip the no-cloud scan (useful when a caller runs it separately). */
  skipNoCloudScan?: boolean;
}

function packageJsonBins(repoRoot: string): { present: boolean; bins: string[] } {
  const path = join(repoRoot, "package.json");
  if (!existsSync(path)) return { present: false, bins: [] };
  try {
    const pkg = JSON.parse(readFileSync(path, "utf8")) as { bin?: unknown };
    if (typeof pkg.bin === "string") return { present: true, bins: ["<default>"] };
    if (pkg.bin && typeof pkg.bin === "object") return { present: true, bins: Object.keys(pkg.bin as Record<string, unknown>) };
    return { present: true, bins: [] };
  } catch {
    return { present: true, bins: [] };
  }
}

export function runRepoConformance(repoRoot: string, options: RepoConformanceOptions = {}): RepoConformanceReport {
  const checks: ConformanceCheck[] = [];
  const loaded: LoadServiceContractResult = loadServiceContractManifest(repoRoot);

  if (!loaded.ok) {
    const issueDetail = loaded.issues
      ? `: ${loaded.issues.map((issue) => `${issue.path.join(".") || "<root>"} ${issue.message}`).join("; ")}`
      : "";
    checks.push({ id: "manifest_valid", status: "fail", detail: `${loaded.error}${issueDetail}` });
    return { ok: false, repoRoot, name: null, class: null, checks };
  }

  const manifest = loaded.manifest;
  checks.push({ id: "manifest_valid", status: "pass", detail: `hasna.contract.json valid for ${manifest.name} (${manifest.class})` });

  // Check 2: bins declared vs package.json bin, and allowlist compliance.
  const allowed = new Set(allowedBinsForName(manifest.name));
  const outOfAllowlist = manifest.bins.filter((bin) => !allowed.has(bin));
  if (outOfAllowlist.length > 0) {
    checks.push({ id: "bins_allowlisted", status: "fail", detail: `bins outside allowlist: ${outOfAllowlist.join(", ")}` });
  } else {
    checks.push({ id: "bins_allowlisted", status: "pass", detail: `bins allowlisted: ${manifest.bins.join(", ") || "(none)"}` });
  }

  const pkgBins = packageJsonBins(repoRoot);
  if (!pkgBins.present) {
    checks.push({ id: "bins_match_package", status: "skip", detail: "no package.json found" });
  } else if (pkgBins.bins.includes("<default>")) {
    checks.push({ id: "bins_match_package", status: "skip", detail: "package.json uses a single string bin" });
  } else {
    const declared = new Set(manifest.bins);
    const missing = manifest.bins.filter((bin) => !pkgBins.bins.includes(bin));
    const undeclared = pkgBins.bins.filter((bin) => !declared.has(bin));
    if (missing.length > 0 || undeclared.length > 0) {
      const parts: string[] = [];
      if (missing.length > 0) parts.push(`declared but missing from package.json: ${missing.join(", ")}`);
      if (undeclared.length > 0) parts.push(`in package.json but undeclared: ${undeclared.join(", ")}`);
      checks.push({ id: "bins_match_package", status: "fail", detail: parts.join("; ") });
    } else {
      checks.push({ id: "bins_match_package", status: "pass", detail: "declared bins match package.json bin" });
    }
  }

  // Check 3: env parsing + mode enum compliance.
  const env = options.env ?? process.env;
  const { modeKeys } = storageEnvKeys(manifest.name);
  const modeEnvHit = modeKeys.map((key) => ({ key, value: env[key]?.trim() })).find((hit) => hit.value);
  if (!modeEnvHit || !modeEnvHit.value) {
    checks.push({ id: "mode_enum_compliance", status: "pass", detail: `no mode env set; defaults to local (keys: ${modeKeys.join(", ")})` });
  } else {
    try {
      const { mode, deprecatedAlias } = normalizeStorageMode(modeEnvHit.value);
      const alias = deprecatedAlias ? ` (deprecated alias '${deprecatedAlias}' -> cloud)` : "";
      checks.push({ id: "mode_enum_compliance", status: "pass", detail: `${modeEnvHit.key} normalizes to '${mode}'${alias}` });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      checks.push({ id: "mode_enum_compliance", status: "fail", detail: `${modeEnvHit.key}: ${message}` });
    }
  }

  // Check 4: health shape when a serve bin exists.
  const hasServeBin = manifest.bins.includes(`${manifest.name}-serve`) || manifest.class === "service" || manifest.class === "saas";
  if (!hasServeBin) {
    checks.push({ id: "health_shape", status: "skip", detail: "no serve bin declared" });
  } else if (options.healthSample === undefined) {
    checks.push({ id: "health_shape", status: "skip", detail: "serve bin present; no health sample provided to shape-check" });
  } else {
    const result = HealthResponseSchema.safeParse(options.healthSample);
    if (result.success) {
      checks.push({ id: "health_shape", status: "pass", detail: "GET /health payload matches { status, version, mode }" });
    } else {
      checks.push({
        id: "health_shape",
        status: "fail",
        detail: `health payload invalid: ${result.error.issues.map((i) => `${i.path.join(".") || "<root>"} ${i.message}`).join("; ")}`
      });
    }
  }

  // Check 5: no forbidden shared cloud runtimes (reuse the no-cloud guard).
  if (options.skipNoCloudScan) {
    checks.push({ id: "no_cloud_guard", status: "skip", detail: "skipped by caller" });
  } else {
    try {
      const pack = scanNoCloudTarget(repoRoot);
      if (pack.verdict === "passed") {
        checks.push({ id: "no_cloud_guard", status: "pass", detail: "no forbidden shared cloud runtime edges" });
      } else {
        const top = pack.findings
          .filter((f) => f.severity === "high" || f.severity === "critical")
          .slice(0, 5)
          .map((f) => `${f.severity} ${f.path ?? "<manifest>"}: ${f.message}`)
          .join("; ");
        checks.push({ id: "no_cloud_guard", status: "fail", detail: top || "no-cloud scan failed" });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      checks.push({ id: "no_cloud_guard", status: "fail", detail: `no-cloud scan error: ${message}` });
    }
  }

  const ok = checks.every((check) => check.status !== "fail");
  return { ok, repoRoot, name: manifest.name, class: manifest.class, checks };
}
